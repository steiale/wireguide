# LockPlus Native: decision, requirements, lessons

This document defines the native Swift rewrite of LockPlus. It records the architecture decision, the requirements, and every lesson the Go/Wails app had to learn, so the native app starts out knowing them.

Sources:
- 276 commits of history and the project memory notes;
- the Fable security review and the Opus code reviews of October 2026;
- research into Apple guidance and open-source apps that ship this stack (sources in the last section).

Status: decided 2026-10-25. Nothing is built yet.

## 1. Decision

LockPlus will only ever target macOS. The rewrite is native Swift:

| Concern | Native design | Replaces (Go app) |
|---|---|---|
| UI | SwiftUI windows + AppKit `NSStatusItem`/`NSMenu` for the menu bar | Wails v3 beta + Svelte + a tray patch + `private_mac_apis` |
| Tunnel host | `NEPacketTunnelProvider` **system extension** (Developer ID) | root LaunchDaemon helper, osascript installer, unix-socket JSON-RPC |
| WireGuard | WireGuardKit, from a fork we maintain built on current wireguard-go | wireguard-go in the root helper + utun |
| OpenVPN | openvpn3 core (MPL-2.0 option) + our own ObjC++ shim | bundled openvpn 2.7 subprocess + management interface |
| Kill switch | `includeAllNetworks` (full tunnel) / `enforceRoutes` (split) | pf anchors |
| DNS | `NEDNSSettings` (`matchDomains: [""]` for full, explicit domains for split) | networksetup/scutil + DNS journal |
| Wi-Fi auto-connect | `NEOnDemandRule` with `ssidMatch` | CoreWLAN polling + Location |
| Secrets | app: data-protection keychain; extension: sealed root-owned 0600 files in its own sandbox container, handed over via XPC (System keychain only as an optional upgrade, see DESIGN §6.3) | legacy file keychain |
| Updates | Sparkle 2 (EdDSA, deltas) | custom GitHub + Ed25519 updater that only revealed the zip |
| Login item | `SMAppService.mainApp` | LaunchAgent plist, later the Wails AutostartManager |
| Build | `xcodebuild archive/export` (Xcode 27+) + `notarytool` + create-dmg | go-task Taskfiles + wails3 CLI |

Why:
- Apple tells VPN apps to migrate to Network Extension and to avoid pf and route-table edits (WWDC25 session 234; TN3165 "pf is not API").
- About 9–10k lines of Go exist only because we run as root: helper, ipc, elevate, firewall, network, most of tunnel, reconnect and ovpn. That is where our recurring bugs and the whole root attack surface lived.
- Wails v3 is a nightly pre-1.0 with a bus factor of about 1, and macOS 27 tray bugs are still open upstream.

What is deliberately NOT carried over:
- Multi-tunnel concurrency. macOS runs only one active packet-tunnel configuration at a time. Decide this before writing any UI.
- openvpn 2.x features that need scripts, plugins or TAP. Profiles that rely on them get a clear "unsupported" message at import.

## 2. Target skeleton

- **`LockPlus.app`**: SwiftUI + AppKit, Sparkle, hardened runtime, not sandboxed.
  - Entitlements: `com.apple.developer.system-extension.install`, NE `packet-tunnel-provider(-systemextension)`, `application-groups` `$(TeamIdentifierPrefix)<bundle-id>`.
- **`LockPlusTunnel.systemextension`** in `Contents/Library/SystemExtensions/`: sandboxed, with `network.client`, `network.server`, the NE entitlement and the same group.
  - `Info.plist`: `NEProviderClasses` → `com.apple.networkextension.packet-tunnel`, plus `NEMachServiceName = $(TeamIdentifierPrefix)<bundle-id>.tunnel.$(CURRENT_PROJECT_VERSION)`. The name changes with every version (see L-EXT-3).
  - WireGuardKit and openvpn3 are embedded **inside** the extension, with rpath `@executable_path/../Frameworks`.
- **SPM packages:**
  - `LockPlusCore`: models, the `.conf`/`.ovpn` parsers and allowlist, the XPC protocol.
  - `TunnelEngine`: provider logic behind protocols, unit-testable outside the NE.
  - `WireGuardBridge`: the forked WireGuardKit; its Go bridge is built by an External Build System target.
  - `OpenVPN3Shim`: ObjC++.
- **Bundle IDs:** new ones, so the native app can be installed next to the Go app (e.g. `io.github.steiale.lockplus.mac` and `.mac.tunnel`), plus a separate Homebrew cask.
- **Profiles:** four provisioning profiles, a development and a Developer ID one for each bundle ID. Development uses the unsuffixed NE value; Developer ID needs `-systemextension` on **both** the app and the extension.
- **Version:** one `xcconfig` value drives `CFBundleShortVersionString` **and** `CFBundleVersion` for the app, the extension and the appcast. CI fails if they disagree.

## 3. Requirements from our own history

Each item: what happened (evidence) → the requirement in the native app → the test that proves it.

### Tunnel lifecycle
- **L-LC-1: no zombie tunnels.** wireguard-go closed its own device after a fatal TUN read error and the UI kept showing "Connected" (e7bbed1). A `select` on two ready channels skipped death handling half the time.
  - Requirement: any engine or openvpn3 fatal error calls `cancelTunnelWithError`. The app's only state source is `NEVPNStatus` plus `fetchLastDisconnectError`.
  - Test: kill the WG backend inside the extension; status must leave `.connected` within 5 s.
- **L-LC-2: "connected" means the data plane is up.** The OpenVPN reconnect returned when the process started, so the kill-switch resume found no interface and stayed off (e7bbed1).
  - Requirement: call the `startTunnel` completion only after openvpn3 reports CONNECTED **and** `setTunnelNetworkSettings` has completed.
- **L-LC-3: every cross-process call has a timeout.** A wedged management socket blocked forever. An RPC timeout shorter than the connect killed the helper. Health pings queued behind Connect caused false "dead helper" verdicts (7a55ba6, aa46660, e7bbed1).
  - Requirement: every XPC call has a timeout, and a slow connect is never mistaken for a dead extension.
- **L-LC-4: one source of truth.** The GUI drifted from reality on tray and Wi-Fi-rule connects (7a6e365, cfc7fe9). Policy such as the kill switch was applied only for connects from one UI path (Opus review H3).
  - Requirement: the policy lives in the configuration (`includeAllNetworks` etc.), never in a UI code path.

### Reconnect, sleep, network change
- **L-RC-1: path changes.** Wi-Fi to Ethernet left the tunnel zombied, because wake was the only trigger (33e2ef6).
  - Requirement: the extension watches `defaultPath`/`NWPathMonitor`, sets `reasserting`, and rebinds.
- **L-RC-2: dead peer.** There was no handshake for 180 s and nothing noticed (de542d0).
  - Requirement: a handshake-age watchdog in the extension (WG) and openvpn3 keepalives.
- **L-RC-3: respect backoff.** Releasing openvpn's hold at once skipped its restart pause and could lock accounts (c15d1ba).
  - Requirement: every retry loop has exponential backoff with a cap.
- **L-RC-4: auth during reconnect.** A 2FA prompt was torn down by the reconnect timeout, and a stale TOTP reply got reused.
  - Requirement: a pending auth prompt pauses the timeout, and stale replies are drained.
- **L-RC-5: sleep/wake.**
  - Requirement: with `disconnectOnSleep=false`, `sleep()` quiesces and `wake()` reconnects with `reasserting=true`; on failure call `cancelTunnelWithError`. Recreate UDP sessions after wake.

### Kill switch
- **L-KS-1: verify behavior, not configuration.** The pf kill switch was a no-op for months because the anchor name was wrong (c9e9ffd). It was also disabled during every reconnect (Opus review, root H1) and failed open when `pfctl -e` failed (b120e52).
  - Requirement: an automated **leak harness** before every release, checking:
    - the extension is killed;
    - reconnect keeps blocking;
    - sleep/wake;
    - a Wi-Fi to Ethernet switch;
    - fragmented and large packets (RDP/SMB);
    - OpenVPN over TCP;
    - DNS (`scutil --dns`, plus querying an external resolver directly).
- **L-KS-2: never toggle `includeAllNetworks` while connected.** Save it only while disconnected.
- **L-KS-3: updates while blocked.** With the kill switch on, an update can leave the Mac offline (Mullvad's experience).
  - Requirement: stop the tunnel before replacing the extension, then reconnect.
  - Test: run a Sparkle update with the kill switch on.
- **L-KS-4: fragments and TCP.** IP fragments and SYN-only TCP state broke RDP and OpenVPN-over-TCP under pf (e7bbed1, c9e9ffd).
  - Requirement: keep these cases in the leak and throughput harness even though pf is gone.

### DNS
- **L-DNS-1: crash leaves no state.** Hijacked DNS survived crashes, which needed a journal (5e5b72b, b120e52). The NE removes the problem.
  - Test: `kill -9` the extension, then check `scutil --dns`.
- **L-DNS-2: every pushed form.** `dhcp-option DNS`/`DNS6`/`DOMAIN-SEARCH`, 2.7 `dns server N`/`search-domains`, PUSH_UPDATE, and DNS defined in the profile itself all appeared (04048ab, c15d1ba). `pull-filter` must be honoured.
  - Requirement: map all of them into `NEDNSSettings`, using `matchDomains` and `matchDomainsNoSearch`.
- **L-DNS-3: diagnostics fail closed.** The leak test reported "safe" when it couldn't read the resolver (c9e9ffd). MDM profiles silently ignored DNS writes.
  - Requirement: after connect, verify the effective resolver.

### MTU and endpoints
- **L-MTU-1.** MTU parsing always fell back to 1420 (c7e3a74), and imported profiles without `mssfix`/keepalive stalled RDP (e7bbed1).
  - Requirement: set `NEPacketTunnelNetworkSettings.mtu` explicitly, try every resolved endpoint IP, and keep MSS/keepalive floors.

### OpenVPN
- **L-OVPN-1: profile validation is an allowlist with a parser identical to the engine's.** A blocklist let profiles make root write and read files, and our tokenizer disagreed with openvpn's on quotes, backslashes and inline close tags (c59eb25).
  - Requirement: port the allowlist and the differential tests (`internal/ovpn/allowlist.go`, `parse.go`, `validate_test.go`). Add a differential test against **openvpn3's** parser.
- **L-OVPN-2: 2.7 compatibility traps.**
  - `cipher X` is no longer a data-cipher fallback; we added a shim for CBC-only servers (04048ab).
  - `verb` must be ≥3 to see PUSH DNS but ≤4 to avoid logging keys (c15d1ba).
  - OpenSSL 4 needs `providers legacy default` for BF-CBC.
  - Requirement: confirm the openvpn3 equivalents in the spike.
- **L-OVPN-3: auth flows.**
  - Combined password+OTP strings, static challenge (SC), dynamic challenge (CRV1, which carries the username in the challenge), and auth-failed re-prompts all occur.
  - Web/SSO auth (`WEB_AUTH`/`OPEN_URL`/`CR_TEXT`) and encrypted keys must not hang; show a clear error or support them.
  - Never advertise `IV_SSO` features we don't implement.
- **L-OVPN-4: errors reach the user.** FATAL, auth failure and missing passwords were silent until a 150 s deadline (c15d1ba).
  - Requirement: every terminal error produces a visible message via `fetchLastDisconnectError`.
- **Spike gate (before any OVPN UI work):** the real **BHP (Sophos)** and **AllService** profiles connect, CRV1 and SC work, a CBC-only server works, and tls-crypt-v2 works.

### Credentials
- **L-CRED-1: keychain location matters.** Writing as root landed items in the System keychain and caused an admin prompt on every connect. `SecItemUpdate` never moved them (e7bbed1, cbd05ce). Secrets were passed in `security` CLI argv. Text encodings mangled bytes. Synchronous keychain shell-outs froze the GUI.
  - Requirement:
    - store raw `Data` through the native API only, never on the main thread;
    - key items by a stable profile UUID, not the display name (a rename orphaned credentials, tunnel_ops.go);
    - the app owns the data-protection copy;
    - the extension owns its own copy, imported over XPC and stored as sealed root-owned 0600 files in its sandbox container; the app never reads it. (Revised 2026-10-25: a sandboxed NE system extension runs into sandbox violations on the System keychain (DTS, forum 672456), `SecAccess` is deprecated, and partition lists can't be set through a supported API (forum 98182). Root ownership is the real boundary, and admin users are out of scope. See DESIGN §6.3);
    - `passwordReference` written by the app is **not** readable from the extension (-25308).

### Menu bar
- **L-MB-1.**
  - Rate calculation: byte and time baselines must update together (0K/0K bug).
  - Use monospaced digits so the label width doesn't jitter (2d08dc8).
  - Rebuild the menu in `menuNeedsUpdate`, so states like ◐ don't go stale (f83384f).
  - Assign `statusItem.menu` natively, with no synthetic clicks; macOS 27 broke the event-monitor path (3f14acd).
  - The tray icon must disappear on quit (92a45b5).
  - Respect `isRemovalAllowed`/"Allow in the menu bar" (macOS 26).
  - The menu bar is 30 pt on Tahoe.

### Install, upgrade, extension lifecycle
- **L-EXT-1: one clear dialog, no retry loops.** Retries caused endless admin prompts (c9e9ffd, 8341d47).
  - Requirement: handle every `OSSystemExtensionRequest` result (needs approval, `.willCompleteAfterReboot`, failure) with one dialog that deep-links to System Settings › Login Items & Extensions.
- **L-EXT-2: activate on every launch.** The request is idempotent. `actionForReplacingExtension` returns `.replace`. Bump **both** version keys on every build, because a version check alone missed a stale binary (805a5fc).
- **L-EXT-3: replacement while connected** breaks XPC (FB17032197). Use a per-version `NEMachServiceName`, and stop the tunnel before replacing.
- **L-EXT-4: uninstall.** Trash doesn't remove system extensions.
  - Requirement: an in-app "Uninstall" removes the configurations, calls `deactivationRequest`, and deletes our keychain items.
- **L-EXT-5:** the extension has **no** AppKit dependency. The root helper crash-looped when it linked GUI frameworks (6330e74).
- **L-EXT-6: dev builds are Developer ID signed.** An ad-hoc NE won't load, as with the helper (8341d47). The debug loop:
  - log "first light" in `main.swift`;
  - Activate/Deactivate buttons in a debug menu;
  - after rebuilds, deactivate and reactivate.

### Updates, signing, distribution
- **L-UPD-1.** The custom updater silently failed its hash check for every non-brew user (installer.go). Asset matching missed "universal" (89747c0). Signatures weren't bound to the version, which allowed a downgrade (dd3b465). Redirect hosts weren't restricted (8f578a8). The release could ship unsigned ("grace mode").
  - Requirement: Sparkle 2 with EdDSA; refuse downgrades; re-activate the extension on the first launch after an update (the system keeps its own copy).
  - Test: an N-1 → N update end to end on every release.
- **L-DIST-1.**
  - The cask zip must contain the exact `.app` name.
  - The old cask's `zap` deleted the new app's data (bb50f10). Audit **every** other cask's zap/uninstall when renaming.
  - Brew detection needs absolute paths, because Finder launches have no PATH (15b0d2a).
  - Set the cask to `auto_updates true`.
- **L-DIST-2.**
  - Check notarization credentials with `notarytool history`, not `security find-generic-password`.
  - Releases fail hard without the signing key.
  - With Xcode ≤26, Developer ID NE exports need a manual inside-out re-sign; Xcode 27 fixes this.

### Data migration
- **L-MIG-1.** Tunnels were lost on the wireguide-plus → lockplus rename (6a1c68c); the fix was copy-only migration plus a marker.
  - Requirement: the native app imports the Go app's tunnels (`~/Library/Application Support/lockplus/tunnels`) and keychain items by **copying**, never deleting. The Go app's final release uninstalls its helper, flushes its pf anchors and restores DNS.

### Security posture to keep
- Import caps: 500 zip entries, 10 MB per entry; no zip-slip (we never unpack to disk).
- Names validated before they touch any path.
- Exports opened `O_NOFOLLOW` at 0600.
- XPC listeners validate the peer's code signature, because the Mach service is global.
- A CSP-equivalent mindset: no web views unless needed. If CodeMirror is kept in a `WKWebView`, give it a strict CSP and no bridge to secrets.
- A mandatory Fable security review for extension, keychain, parser and XPC code; Opus for architecture; fix **every** finding.

## 4. Best-practices checklist (research, Oct 2026)

Pitfalls to avoid:
1. Xcode ≤26 Developer ID export of NE apps (fails at runtime with "Plugin failed").
2. A missing `-systemextension` suffix or profile on app **or** extension.
3. Frameworks or rpaths only in the app bundle.
4. Expecting the data-protection keychain or `passwordReference` to work in the extension.
5. A static `NEMachServiceName` combined with replacement while connected.
6. Not bumping both version keys.
7. Relying on Trash to uninstall.
8. Toggling `includeAllNetworks` while connected.
9. An update with the kill switch on leaves the Mac offline.
10. Calling `exit()` or `stopTunnel` from the provider; use `cancelTunnelWithError`.
11. No `reasserting` on wake or path change.
12. Split DNS without a `""` catch-all leaks.
13. Assuming SSID access without Location.
14. Re-registering the login item on every launch (undoes the user's choice).
15. Building on unmaintained wireguard-apple without a pinned fork.

Practices:
- Cache `NETunnelProviderManager`s; repeated `loadAllFromPreferences` leaves stale managers firing notifications.
- Use one manager per profile.
- Keep `providerConfiguration` small and free of secrets.
- Use XPC via `NEMachServiceName` (`NSXPCConnection(machServiceName:options:.privileged)`) for app ↔ extension; `sendProviderMessage` only for trivial calls. A nil reply means delivery failed.
- Set `excludeLocalNetworks`, `excludeAPNs`, `excludeCellularServices` and `excludeDeviceCommunication` explicitly.
- Use TN3165's compatibility list as a test matrix: AirDrop, Continuity, Internet Sharing, Xcode device debugging.
- Local Network privacy applies to the app if it probes LAN hosts, not to the root extension (TN3179).
- On-demand rules are evaluated by the system: prototype them with a configuration profile first.

## 5. Phased plan (about 77–106 developer-days after the October 2026 design review; was 65–95)

0. **Done in Go (v1.1.0):** dependency upgrades, security hardening, review fixes. The Go app stays the release line until parity.
1. **Spike (15–20 d, re-estimated in DESIGN §18, including test-server infrastructure):** an openvpn3 shim connecting BHP and AllService with CRV1/SC, plus WireGuardKit (forked, current wireguard-go) in one system extension. Answer the open questions below. **Go/no-go for OpenVPN-in-NE.**
2. **WireGuard beta (about 20 d):**
   - Xcode project, extension activation, WG tunnel;
   - `includeAllNetworks`, `NEDNSSettings`, the two keychain stores;
   - importer from the Go app, Developer ID export and notarization, DMG, a separate cask;
   - Sparkle and the update-with-extension-replacement flow (moved here from phase 4, because the beta's N-1 → N update test needs it).
   - Coexistence: refuse to connect while the Go helper's pf anchor is loaded.
3. **OpenVPN (20–30 d):** shim hardening, the auth UI (password, SC, CRV1), the profile allowlist port, a corpus test of the real profiles, an "unsupported directive" report at import.
4. **UI parity (15–25 d):**
   - menu bar states and rates, tunnel list and detail, editor;
   - stats (Swift Charts), history, logs (`OSLog`), export/export-all;
   - on-demand Wi-Fi rules, settings, onboarding;
   - String Catalogs (en/de/ko/ja);
   - `SMAppService.mainApp`, in-app Uninstall.
5. **Cutover (5–10 d):** the Go app's final release runs its uninstaller (helper, pf, DNS). The native app becomes the `lockplus` cask; the old cask is retired.

## 6. Open questions for the spike

1. Does `ssidMatch` work without Location on macOS 15/27?
2. How do `includeAllNetworks` and the exclude flags behave on macOS 15/26/27: for AirDrop, Xcode device debugging and Sparkle while blocked, and does traffic stay blocked after provider `kill -9`, `stopVPNTunnel` and `cancelTunnelWithError`? Does it break the provider's own TCP connects, such as OpenVPN over TCP (DESIGN §10.1.1)?
3. ~~Does `NEDNSOverHTTPSSettings` inside tunnel network settings work on macOS?~~ Deferred: DoH/DoT is cut from v2.0 (DESIGN §21).
4. Extension secret storage: do root-owned container files work from the sandboxed extension across replacement, and can a CryptoKit Secure Enclave key wrap their file key (forum 804612)? The System keychain is tested only as an optional upgrade.
5. Is `sendProviderMessage` enough, or is XPC required? Does the per-version Mach name have side effects?
6. Does the extension's root context get the TN3179 exemption?
7. Can WireGuardKit (Go runtime) and openvpn3 (asio + OpenSSL) coexist in one extension process?
8. Do openvpn3 CRV1 and static-challenge flows work through our shim?
9. Does an Xcode 27 export work end to end for Developer ID (so we can drop the manual re-sign)?
10. Does a Sparkle update correctly replace the extension while connected and while the kill switch is on?

## 7. Process rules carried over

- One version source, enforced in CI. A drift between `fallbackVersion` and Info.plist caused an infinite reinstall loop.
- Every security toggle gets a **behavioral** test. Three features shipped as silent no-ops: the pf anchor, OVPN auto-reconnect, and the updater hash gate.
- Review by lens:
  - Sonnet first pass;
  - Opus architecture and full review;
  - Fable mandatory security pass on extension, keychain, parsers and XPC.
  - Fix all findings.
- Never hand-run code generators with guessed flags, and never keep build patches in `/tmp`; vendor them in the repo.
- Release:
  - confirm scope on a bare "deploy";
  - confirm every push separately;
  - run an N-1 → N upgrade test with real data;
  - check notarization with `notarytool history`.
- Debugging: a silent gap in the extension log during a reported freeze points at the app process. Cross-check rates against `netstat -ibn`.

## Sources

Apple:
- WWDC25 session 234: https://developer.apple.com/videos/play/wwdc2025/234/
- TN3165, pf is not API: https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api
- TN3134, NE provider deployment: https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
- TN3179, Local Network privacy: https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy

Apple Developer Forums:
- Developer ID NE export / `-systemextension` suffix: https://developer.apple.com/forums/thread/737894
- Packaging, XPC, app groups: https://developer.apple.com/forums/thread/800887
- XPC breaks after replacement while connected (FB17032197): https://developer.apple.com/forums/thread/779395
- System keychain hand-off pattern: https://developer.apple.com/forums/thread/680013
- Sysex keychain limits (sandbox violations on the System keychain): https://developer.apple.com/forums/thread/672456, https://developer.apple.com/forums/thread/824202
- No supported partition-list API: https://developer.apple.com/forums/thread/98182
- Secure Enclave keys from daemons via CryptoKit: https://developer.apple.com/forums/thread/804612
- XPC code-signing requirement enforced on the first message: https://developer.apple.com/forums/thread/760287
- `passwordReference` not readable in the extension: https://developer.apple.com/forums/thread/672748
- Stopping vs. cancelling the tunnel: https://developer.apple.com/forums/thread/772393
- Sleep/wake: https://developer.apple.com/forums/thread/95988
- Toggling `includeAllNetworks`: https://developer.apple.com/forums/thread/731793
- On-demand rules and SSID: https://developer.apple.com/forums/thread/813746
- Menu bar visibility (macOS 26): https://developer.apple.com/forums/thread/788101
- Extension debugging: https://developer.apple.com/forums/thread/725805
- Extension after a Sparkle update: https://developer.apple.com/forums/thread/732624

Other:
- System extension deletion: https://obdev.at/blog/deletion-impossible-2
- Tailscale macOS variants: https://tailscale.com/kb/1065/macos-variants
- OpenVPN Connect and NE: https://openvpn.net/connect-docs/macos-network-extension.html
- openvpn3 licence: https://raw.githubusercontent.com/OpenVPN/openvpn3/master/LICENSE.md
- wireguard-apple history: https://git.zx2c4.com/wireguard-apple/log/
- Partout (GPL, architecture reference only): https://github.com/partout-io/partout
- Mullvad on `includeAllNetworks`: https://cyberinsider.com/mullvad-vpn-explains-why-it-holds-back-key-ios-privacy-feature/
- Privacy Guides, macOS VPN expectations: https://discuss.privacyguides.net/t/what-should-we-require-of-vpn-providers-on-macos/36175
