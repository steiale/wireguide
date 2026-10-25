# LockPlus Native: technical design

Status: draft 3, 2026-10-25 (security design review and its re-review applied; see the revision log). Implements the decision in [`../NATIVE-REWRITE.md`](../NATIVE-REWRITE.md) (cited below as **NR**). Every `L-*` requirement in NR §3 is addressed by name; §19 maps each one to the section that satisfies it and to its test.

This document is written for one developer working with AI coding agents. Every section ends in something implementable: a type, a sequence, a rule, or a test. Where Apple behaviour is uncertain, the text states the **assumption**, the **spike** that validates it (§17), and the **fallback**.

Conventions:
- `MUST`/`MUST NOT` are hard rules. Reviewers reject code that breaks them.
- **Decision** marks a choice this document makes that NR leaves open.
- Team ID: `M53GHX9FAY`. App bundle ID: `io.github.steiale.lockplus.mac`. Extension: `io.github.steiale.lockplus.mac.tunnel`.
- **TBD-by-Sn** marks an expected outcome that spike Sn must confirm before code depends on it. Every TBD has a designed response for each possible result.

## Revision log

### Draft 3

Draft 3 applies the re-review of draft 2. Claims were checked against primary sources: openvpn3 `master` (`openvpn/tun/builder/client.hpp`, `openvpn/tun/persist/tunwrap.hpp`, `openvpn/tun/tunio.hpp`, `openvpn/client/cliopt.hpp`, `openvpn/client/cliproto.hpp`, `openvpn/client/cliconnect.hpp`, `openvpn/client/clicreds.hpp`, `openvpn/ssl/proto.hpp`); wireguard-apple `Sources/WireGuardKitGo/api-apple.go`; the Sparkle documentation ("Rotating signing keys", Security settings); and the macOS SDK headers `NetworkExtension/NEVPNProtocol.h`, `NEOnDemandRule.h` and `ServiceManagement/SMAppService.h`.

| ID | Change |
|---|---|
| N1 (High) | CI only builds and tests; it holds **no** Developer ID identity, provisioning profile, notarization key or EdDSA key. The release archive, Developer ID signing, notarization, stapling and EdDSA signing all run on the dev Mac from a clean checkout of the signed tag (`Tools/release/release.sh`). Optionally CI builds the same tag unsigned and the dev Mac compares binary hashes (non-gating until the build is shown to be reproducible). Key rotation: Sparkle allows changing the EdDSA key under `SUVerifyUpdateBeforeExtraction` **only** if the update is a Developer ID-signed DMG. **Decision:** regular items stay zips; the §1.3 A5 recovery path publishes a rotation release whose enclosure is the signed, notarized DMG (§1.3 A5, §1.4, §2.7, §12.1, §12.2, §12.4, §15.6, §20). |
| N2 (Medium) | openvpn3's `TunBuilderClient` hands the fd from `tun_builder_establish()` to a `TunPersist` (`ScopedFD`), which on macOS is `NO_RETAIN` and **closes** it on teardown; with `tunPersist = false` it is short-term and re-established on every reconnect. The shim returns `dup(fd)` of the NE utun fd (wireguard-apple dups too, `api-apple.go:91–103`), and S11 evaluates `tunPersist = true` (§7.3, §7.2 `holdBlocked`, §17 S11). Also found: `cliopt.hpp` sets `tun_prefix = true` on macOS, so the builder client already handles the 4-byte AF header. |
| N3 (Medium) | A pause now survives an app crash: a bundled `SMAppService.agent` runs `LockPlus --resume-protection` while a pause is active and is unregistered on resume. `StartCalendarInterval` at `pausedUntil` is **not** usable: SMAppService only registers plists inside the signed bundle (static), and `StartCalendarInterval` is a recurring calendar match, not an absolute date. The closest public mechanism is a static agent with `StartInterval = 60` + `RunAtLoad`, which exits immediately until `pausedUntil` has passed (§10.4, §11.3, §20). |
| N4 (Medium) | The IPv6 blackhole for v4-only full tunnels now follows `killSwitch` (default), with an optional per-profile "Block IPv6 without the kill switch" toggle. Kill switch off means v6 goes to the LAN, as in the Go app, which only blocked v6 with the kill switch on. Reason: silent drops cause timeouts for clients without Happy Eyeballs, and the blackhole also captured LAN v6 (§3.1, §10.5, §15.3 LK-09, §20; supersedes the draft 2 M5 decision). |
| N5 (Low) | §12.3 disables on-demand on **every** owned manager before replacement, mirroring §4.2 step 3; `pendingResume` records each one. S2 adds "save on-demand rules while connected" (§4.2, §12.3, §17 S2). |
| N6 (Low) | Metadata replay: `Profile.metaRevision` (inside the MAC) is mirrored to `providerConfiguration.metaRev`. Reconcile never writes NE preferences or provisions from metadata older than the manager's copy (§3.1, §3.3, §3.4, §15.1, §15.6). |
| N7 (Low) | The on-demand probe depends on one host. Documented, and every connect rule now has a second rule probing a different HTTPS host (§10.4, §20). |
| N8 (Info) + M6 note | The openvpn3 patch exposes only `purge_user_pass()`. `NEED_CREDS` is thrown in `client_auth` **before** the auth string is written (so a purged OTP never reaches the server) and is **fatal** (`cliconnect.hpp` stops the client), and the purge clears the username too. The `awaitingAuth` path therefore re-supplies the username and calls a fresh `connect()`. Also found: openvpn3 honours `auth-nocache` natively with the same purge; S8 evaluates it as a patch-free alternative (§8.4, §17 S8, §18 P3, §20). |
| H3 nit | §8.5: `remote_bypass` is set in the non-agent native-tun paths (`tun/mac`, `tun/win`, with `tunPersist`) and, under `USE_TUN_BUILDER`, only on iOS with `tunPersist`. The conclusion stands: on macOS the endpoint exclusion is our job. |
| H1 extra | The `includeAllNetworks` header says "traffic necessary for connecting to captive networks" is always excluded. Noted in §10.1 and §10.4; S1 records what that covers in practice. |
| Drifts | NR §5 phase days now match §18 (P2 24 d, P4 13–22 d). The Mach service name is spelled `…tunnel.v$(CURRENT_PROJECT_VERSION)` in both documents. §6.8 has one detection rule (payload-key item missing ⇒ locked; no HMAC inference) consistent with "a new key is never generated over existing files" and §15.1. |

### Draft 2

Draft 2 applies the security design review of draft 1. Each finding was checked against primary sources (openvpn3 `master`: `openvpn/client/cliopt.hpp`, `client/ovpncli.{hpp,cpp}`, `openvpn/client/cliconstants.hpp`, `openvpn/tun/builder/client.hpp`, `openvpn/tun/client/tunprop.hpp`, `openvpn/tun/mac/client/tunsetup.hpp`, `openvpn/client/clicreds.hpp`; Apple forums 672456, 680013, 824202, 98182, 804612, 760287; Sparkle documentation; the Go app's `internal/helper/firewall.go`, `internal/firewall/darwin.go`, `internal/ipc/peercred_*.go`, `internal/ovpn/allowlist.go`).

| ID | Change |
|---|---|
| C1 | The extension's primary secret store is now root-owned 0600 files in its sandbox container, sealed with a file key; spike S4 tests wrapping that key with a CryptoKit Secure Enclave key, with a plain root-file key as the fallback. The System keychain is demoted to an optional S4 upgrade. Root ownership is stated as the real boundary; admin users are out of scope (§1.3 A2/A6, §3.3, §6.3, §17 S4, §20). Nuance: DTS does not forbid the System keychain outright (824202: "That's what I'd use"), but 672456 reports sandbox violations for a sandboxed NE sysex, `SecAccess`/`SecTrustedApplication` are deprecated, and 98182 confirms there is no supported way to set partition lists. The change stands. |
| H1 | `includeAllNetworks` semantics are now TBD-by-S2 expectations. S2 measures provider `kill -9`, `stopVPNTunnel`, `cancelTunnelWithError`, OVPN over TCP and provider TCP connects on 15/26/27. LK-02 has one expected outcome. §10.1 designs the app's behaviour for each S2 result, including replicating the Go app's fail-closed-on-death, and documents regressions against the Go kill switch (§10.1.1). |
| H2 | `actionForReplacingExtension` is now a pure, synchronous compare. Quiescing happens **before** any activation request is submitted, driven by `propertiesRequest`. This covers drag-replace and `brew upgrade` while the app was closed with the tunnel up (§4.2, §4.3, §12.3). |
| H3 | `EngineSupport` is generated from openvpn3's `settings_*` lists and verified by constructing `ClientOptions` per directive. `validateProfile` constructs `ClientOptions`, so `UNUSED_OPTIONS` surfaces at import. Canonical size is capped at 256 KiB and lines at 512 bytes. `USE_TUN_BUILDER` is mandatory and `tun/mac/client` is excluded from the build. The endpoint is protected with `tunnelRemoteAddress` plus an excluded host route instead of dropping routes. `ProvideCreds` assumptions are corrected (§8.1, §8.2, §8.4, §8.5, §2.2). Found during verification: `topology`, `route-gateway`, `ping-timer-rem`, `socks-proxy`, `verify-hash` and `dh` are fatal in openvpn3 when left untouched, but the Go allowlist accepts them, so draft 1's "mapped" rows were wrong. |
| M1 | Sparkle accepts a changed code-signing identity whenever EdDSA validates (documented key-rotation behaviour), so "team match" is not a control. Archives and the appcast are signed on the dev Mac; the EdDSA key never enters CI. The XPC team pin and the same-team requirement for system extension replacement are named as the blast-radius limits (§1.3 A5, §12.1, §12.4). |
| M2 | Adds a user-initiated, confirmed "Reinstall tunnel component" path (deactivate → activate) for legitimate rollbacks (§4.2, §4.6, §12.1). |
| M3 | The leak harness drives the shipped release candidate through `scutil --nc`, the shipped UI/file-open paths and Sparkle channels. Fault injection lives in a separate, non-gating `FaultInjection` build (§15.2, §15.3). |
| M4 | Captive portals: `probeURL` on the on-demand connect rule, an Ignore fallback rule, and a "Pause protection for N minutes" action with its UX (§10.4, §11.3). |
| M5 | **Decision:** v4-only full-tunnel profiles route `::/0` into the tunnel as a blackhole, whatever the kill-switch setting; the import report notes it (§9.3, §10.5, LK-09). |
| M6 | S8 verifies `auth-token` push on BHP/AllService. Without a session token, the shim purges cached credentials after CONNECTED for OTP profiles, so engine-internal reconnects go through the prompt (§8.4, §17 S8). |
| M7 | Sparkle and §12.3 move from P4 into P2c (the WireGuard beta's DoD needs an N-1→N update). P1 is re-estimated at 15–20 days, and the test infrastructure is specified (§15.7, §18). |
| M8 | **Decision:** state the limit honestly. The LAContext gate is enforced by our code, not by the OS; why it still holds against the A6 adversary, and where it does not, is spelled out. An OS-enforced reveal key is listed under Later (§1.3 A6, §21). |
| L-sig | The requirement strings pin Developer ID by certificate OIDs with a quoted team ID; the Apple Development clause is gone; first-message enforcement is noted. The audit-token pre-check was **rejected**: `NSXPCConnection.auditToken` is not public API. A replacement rule is given (§5.3). |
| L-A1 | The launch-constraints claim is dropped (none are configured; **Decision:** not in v2.0). Profile metadata JSON is HMAC'd with a key derived from the sealing key (§1.3 A1, §3.3, §3.4). |
| L-TM | Restoring Time Machine to a new Mac loses the `ThisDeviceOnly` sealing key. This is documented, with an export-all nudge and a "profiles locked" recovery UX; passphrase-encrypted export goes under Later (§3.3, §6.8). |
| L-IPC | The Go IPC authenticates by uid only, so the Farewell `Uninstall` RPC is a same-user DoS (stated). A crashed Go helper with pf loaded is detected through the `pf-was-enabled` marker without root (§4.5, §13.3). |
| L-cask | The cask uninstall stays `must_succeed: false`; a possible admin dialog during deactivation is documented (§4.4, §12.2). |
| L-cut | Cut from v2.0 and moved to §21 "Later": the Linux fuzz build and C++ differential harness (replaced by macOS `-sanitize=fuzzer`), Tart VMs with MDM-scripted approval, DoH/DoT (S3), `ssidProfileMap`, ICMP from root, and the per-connection token bucket. |

---

## 0. Scope and non-goals

In scope:
- Feature parity with Go LockPlus v1.0.68+ for one active tunnel at a time:
  - tunnel list and detail, editor with validation;
  - import (file, drag-drop, QR, zip), export and export-all;
  - live stats, history, logs, Wi-Fi auto-connect, diagnostics (latency, DNS check, routes);
  - onboarding, settings, menu bar rates, en/de/ko/ja.
- WireGuard and OpenVPN in one `NEPacketTunnelProvider` system extension.
- Migration from the Go app, and that app's retirement.

Non-goals (NR §1):
- multi-tunnel concurrency;
- openvpn 2.x scripts, plugins, TAP, `management`;
- Intel builds.
  - **Decision:** arm64 only, like the Go app. This removes a whole axis from the wireguard-go and OpenSSL build matrix.
- Web/SSO OpenVPN auth. It is detected and reported, never advertised (L-OVPN-3).

**Decision:** the minimum OS is **macOS 15.0**. This gives `@Observable`, `NSXPCConnection.setCodeSigningRequirement`, `fetchLastDisconnectError`, `excludeDeviceCommunication` (14.4+) and `SMAppService`. CI and the leak harness run on 15, 26 and 27.

**Decision:** Swift 6 language mode with strict concurrency, in every target.

---

## 1. System context and trust boundaries

### 1.1 Components

```
 ┌────────────────────────── user session (uid = alex) ───────────────────────────┐
 │  LockPlus.app (hardened runtime, NOT sandboxed, Developer ID)                    │
 │   SwiftUI windows · MenuBarController · ProfileStore · CredentialStore(app)     │
 │   Sparkle 2 · SystemExtensionManager · TunnelServiceClient (XPC)                │
 │   ~/Library/Application Support/io.github.steiale.lockplus.mac/  (0700)          │
 │   Data-protection keychain, group M53GHX9FAY.io.github.steiale.lockplus.mac     │
 └───────────────┬─────────────────────────────┬──────────────────────────────────┘
       NETunnelProviderManager API         NSXPCConnection(machServiceName: …tunnel.vN,
       (start/stop, NEVPNStatus,           options: .privileged), both ends pin code signature
       fetchLastDisconnectError)                │
 ┌───────────────▼──────────────┐   ┌──────────▼─────────────────────────────────────┐
 │ nesessionmanager / NE prefs  │──▶│ LockPlusTunnel.systemextension (root, sandboxed) │
 │ (system-wide VPN configs,    │   │  PacketTunnelProvider → TunnelController (actor) │
 │  on-demand evaluation)       │   │  WireGuardAdapter (wireguard-go)                 │
 └──────────────────────────────┘   │  OpenVPNAdapter (openvpn3 + OpenSSL 3.5)         │
                                    │  TunnelServiceListener (XPC)                     │
                                    │  Secret files (root 0600, own sandbox container) │
                                    └──────────┬──────────────────────────────────────┘
                                               │ UDP/TCP to VPN servers (bypasses tunnel)
                                       ┌───────▼────────┐
                                       │ Internet / LAN │  VPN servers, DNS, appcast host
                                       └────────────────┘
 Sparkle: appcast (GitHub Pages, HTTPS, signed feed) + archives (GitHub Releases, EdDSA)
```

### 1.2 Trust boundaries

| # | Boundary | Crossing data | Who must distrust whom |
|---|---|---|---|
| B1 | App ↔ extension (XPC) | profile payloads, credentials, auth answers, status/stats/logs | **The extension distrusts the app's input**: it re-validates every payload (§8.1). Both verify the peer's code signature (§5.3). |
| B2 | App/ext ↔ NE preferences | non-secret profile config | Readable by any local admin and visible in System Settings, so it holds no secrets (§3.3). |
| B3 | User ↔ app (files, QR, zip, clipboard) | untrusted profiles | Every parser treats its input as hostile, with caps (§3.5, §8.1, §9.1). |
| B4 | Extension ↔ VPN server | handshake, pushed options, packets | A server can be malicious or MITM'd. Pushed options are allowlisted (§8.5). |
| B5 | App ↔ update channel | appcast, archives | The EdDSA key is the trust anchor (Sparkle accepts a changed code-signing identity when EdDSA validates). Signed feed, no automatic downgrades (§12). |
| B6 | Extension ↔ its secret store | secrets at rest | Root ownership (0600 files in the extension's sandbox container) is the boundary. Any admin can become root, so admins are out of scope (§6.3). |
| B7 | App ↔ legacy Go app | tunnel files, legacy keychain, helper socket | Read-only and copy-only. Legacy data is validated like any import (§13). |

### 1.3 Threat model (STRIDE per adversary)

**A1. Local malware running as the same user (no root, no TCC grants).**
- *Spoofing:* it connects to our Mach service and pretends to be the app.
  - Mitigation: the listener sets `setConnectionCodeSigningRequirement` (§5.3), so an unsigned or foreign-team peer is invalidated on its first message, before any handler runs.
- *Tampering:* it modifies `/Applications/LockPlus.app`, which a drag-install leaves user-writable.
  - Mitigation: a modified bundle fails dynamic code validation, so the extension refuses it, and the hardened runtime blocks DYLD injection. A modified app also loses access to the data-protection keychain items of our access group, so it cannot unseal anything.
  - **Decision:** no launch constraints in v2.0 (draft 1 claimed they re-check; none were configured). Gatekeeper only assesses quarantined first launches, so it is not counted as a control here. Launch/environment constraints are listed under Later (§21).
- *Tampering:* it rewrites `profiles/*.json` metadata, hoping the app faithfully re-saves a weakened policy (e.g. `killSwitch = false`) to NE preferences on the next reconcile.
  - Mitigation: each metadata file carries an HMAC-SHA256 over its canonical JSON, keyed by a subkey derived from the sealing key (§3.4). Same-user code cannot read the sealing key, so it cannot forge the HMAC. A mismatch quarantines the file and never propagates to NE preferences.
  - Replaying an older, validly MAC'd file is caught by the `metaRevision` counter inside the MAC, compared against the NE manager's `metaRev` before any re-save (§3.4, N6).
  - The extension takes policy only from NE preferences (written through `nesessionmanager`, not a user-writable file) and from its own provisioned copy.
- *Information disclosure:* it reads App Support.
  - Mitigation: payloads are AES-GCM-sealed with a key in the data-protection keychain (§3.4). Same-user code without our team signature cannot read that key.
  - Credentials live only in the keychains.
  - **This is an improvement over the Go app, which kept plaintext 0600 files.**
- *Information disclosure:* it reads unified logs.
  - Mitigation: secrets never reach `Logger` (§14). Dynamic strings are `.private`.
- *Denial of service:* it runs `scutil --nc stop`, kills the app, or floods XPC.
  - Accepted, because same-user code can always disrupt.
  - Kill-switch profiles are expected to fail closed while reasserting (TBD-by-S2; §10.1). What happens after `scutil --nc stop` or after the provider is killed depends on S2, and §10.1 defines the response to each result.
  - The XPC listener enforces size caps and per-handler deadlines (§5.4). There is no per-connection rate limiting in v2.0 (§21): same-user code can flood XPC anyway, and that only costs it CPU.
- *Elevation of privilege:* it uses the root extension as a confused deputy (file read/write, exec).
  - Mitigation: the extension is sandboxed and exposes no path-taking or exec-taking API.
  - Profiles go through an allowlist with no path directives (§8.1), and openvpn3 has no script hooks.

**A2. Other local users.**
- NE configurations are system-wide, so another user can see the profile names in System Settings and start them.
- *Disclosure:* a non-admin user cannot read the payload or credentials. App Support is 0700, the data-protection keychain is per-user, and the extension's secret files are root-owned 0600 (§6.3).
- **Out of scope: admin users.** An admin can become root and read the extension's secret files, the extension's memory, and anything else root can. Root ownership is the real boundary of the extension store; no keychain ACL would change that (an admin can also unlock the System keychain). This is stated in the user docs.
- *Tampering:* another user's copy of LockPlus can see our managers through `loadAllFromPreferences`.
  - Mitigation: `providerConfiguration.ownerUID`. The app hides and refuses to edit foreign profiles.
  - The extension enforces ownership on every profile-scoped XPC call using the peer's `effectiveUserIdentifier` (§5.4).
- *Residual risk:* another user can toggle a tunnel from System Settings. This is documented and inherent to macOS.

**A3. Malicious profiles (.ovpn/.conf/zip/QR from an attacker).**
- Root file read/write, library loading and exec through directives.
  - Mitigation: an allowlist, the openvpn-exact tokenizer, and a canonical re-serialization verified by openvpn3's own parser and by constructing openvpn3's `ClientOptions` (§8.1).
  - The extension re-validates the profile and runs sandboxed. openvpn3 is built with `USE_TUN_BUILDER` only, so no code path can shell out to `route`/`ifconfig` (§8.1).
- Parser memory-safety bugs in openvpn3's C++.
  - Mitigation: libFuzzer + ASan on the shim's parse entry point, built on macOS (§15.4).
  - The extension parses only canonical text it generated itself after validation.
- Zip bombs and zip-slip.
  - Mitigation: 500 entries max, 10 MiB per entry decompressed, 1 MiB per raw profile (256 KiB canonical, §8.1), and nothing is unpacked to disk.
- QR decompression bombs.
  - Mitigation: 20 MiB per image and 64 Mpx maximum, decoded by Vision.
- Display-name injection.
  - Mitigation: names never touch a path (UUID keys) and are validated (§3.1).
- An export-time injection into wg-quick (newline in a value).
  - Mitigation: the validator rejects `\r`/`\n` in every value, a port of `internal/config/validator.go`.

**A4. Malicious or MITM VPN server.**
- *Spoofing:* a WireGuard peer is authenticated by its key.
  - OpenVPN uses `remote-cert-tls`/`verify-x509-name` from the profile. **Decision:** if a profile has neither `remote-cert-tls server` nor `verify-x509-name`/`peer-fingerprint`, import warns with "server identity not pinned" (not fatal, for compatibility).
- *Tampering* through pushed options:
  - routes are clamped (§8.5); `redirect-gateway` changes no local policy;
  - DNS is applied only through `NEDNSSettings`;
  - nothing pushed can execute anything;
  - `auth-token` is stored in memory only, never logged.
- *Disclosure:* the server pushes routes to capture LAN traffic (TunnelVision/TunnelCrack).
  - With the kill switch on, `includeAllNetworks` defeats DHCP option 121.
  - **Decision:** `excludeLocalNetworks` ("Allow LAN") defaults to **off** for kill-switch profiles (LocalNet attack) and is a visible per-profile toggle.
- *Denial of service:* the server refuses or drops the connection.
  - Mitigation: capped backoff (L-RC-3). Stored credentials are never auto-retried after AUTH_FAILED (account lockout).
- *Elevation:* a memory bug in openvpn3 or wireguard-go reachable from the network.
  - Mitigations: sandboxed extension; pinned, current upstreams; fuzzing; OpenSSL 3.5 LTS updates tracked in a monthly dependency job.

**A5. Compromised update channel.**
- Attack: a replaced appcast or archive.
  - Mitigation: an EdDSA signature on every archive with the public key in Info.plist, and `SURequireSignedFeed` (Sparkle ≥ 2.9).
  - HTTPS only.
  - **Not a control:** Sparkle's code-signing check. Sparkle documents that an update may change *either* the Apple code-signing certificate *or* the EdDSA key (key rotation), so an archive signed by a different Developer ID team is accepted whenever its EdDSA signature validates. The EdDSA key is therefore the single trust anchor.
- Attack: a downgrade to a vulnerable build.
  - Mitigation: Sparkle never offers a lower version, and our `bestValidUpdate` filter drops them (§12.1).
  - The app never submits an activation request for a lower extension version on its own; `actionForReplacingExtension` returns `.cancel` for a lower version (§4.3). The only downgrade path is the user-initiated, confirmed "Reinstall tunnel component" (§4.6).
- Attack: a stolen EdDSA key.
  - Mitigation: the key never enters CI. Archives and the appcast are signed on the dev Mac (`sign_update`/`generate_appcast` reading the key from the login keychain), with an offline backup in 1Password (§12.1).
  - **The dev Mac also builds what it signs (N1).** If CI built and notarized the archive and the dev Mac only EdDSA-signed it, a CI compromise could still get any binary signed: the dev Mac would sign whatever CI produced. CI therefore holds no Developer ID identity, no provisioning profile, no notarization key and no EdDSA key, and produces no release artifact. The release archive is built, Developer ID-signed, notarized, stapled and EdDSA-signed on the dev Mac from a clean checkout of the signed release tag (§12.4). A CI compromise can then tamper only with CI results (tests), not with anything users install.
  - **Blast-radius limits if the key is stolen anyway:** a different-team app installed this way (a) fails the extension's XPC requirement, which pins team `M53GHX9FAY` (§5.3), so it cannot reach provisioned secrets; (b) cannot replace our system extension, because the system only replaces an extension with one from the same team; (c) cannot read the app's data-protection keychain items, whose access group is bound to our team's provisioning profile, so sealed payloads stay sealed. Notarization is **not** claimed as a limit: Sparkle-installed updates are not quarantined, so Gatekeeper does not assess them. What the attacker does get is code execution as the user (A1 capabilities) plus the user's trust in the app name. Recovery: rotate the key with a Developer ID-signed update (Sparkle's rotation rule) and publish an advisory.
  - **Rotation constraint (N1):** with `SUVerifyUpdateBeforeExtraction = YES` (§12.1), Sparkle allows an update that changes the EdDSA key **only if the update archive is a Developer ID code-signed disk image** (Sparkle docs, "Rotating signing keys"). Regular items are zips (§12.2), so the rotation release uses the DMG as its enclosure: **Decision:** the recovery path publishes one appcast item whose enclosure is the Developer ID-signed, notarized `LockPlus-<ver>.dmg`, carrying the new public key in `SUPublicEDKey`; later items return to zips signed with the new key. The feed itself is still signed with the old key, which we still hold when the key was stolen rather than lost. If the old key is lost, users only see the rotation item after `SUSignedFeedFailureExpirationInterval` (default 20 days), without release notes. The DMG path is rehearsed once before GA (§15.5).

**A6. Physical access to an unlocked Mac.**
- Exporting or viewing secrets.
  - Mitigation: Reveal, Edit-config, Export and Export-all require `LAContext` `.deviceOwnerAuthentication`, with a 60 s reuse window.
  - **Limit, stated honestly (M8 decision):** the gate is enforced by **our code**, not by the OS. The sealing key and the saved credentials are readable by the app without user presence, because provisioning and reconcile must run unattended. The gate holds against the A6 adversary only because that adversary can't run code inside our signed process: the hardened runtime blocks injection, a modified bundle loses keychain access, and same-user tools such as Terminal or `security` aren't in our access group. It does **not** hold against a bug in our app that reaches `payload(for:)` without the gate, or against an admin (A2). A unit test asserts that every UI path to plaintext goes through `RevealGate`.
  - **Decision:** no separate OS-enforced reveal key in v2.0. The candidate design (an HPKE copy of each payload sealed to a Secure Enclave key with `SecAccessControl(.userPresence)`) is in §21.
- Disconnecting the VPN or disabling the kill switch.
  - Possible by design for the user. Changing the kill switch requires the tunnel to be disconnected (L-KS-2), so it is visible.
- Reading the extension's secret files.
  - Requires root, i.e. an admin password (out of scope, A2). With the S4 Secure Enclave wrap, a copied file or disk image is useless on another machine. On this Mac, a live root process can still use the wrapped key.

### 1.4 Security invariants (checked in review and in tests)

1. No secret in `providerConfiguration`, `UserDefaults`, plaintext files, logs, crash reports, XPC error strings or `NSError.userInfo`.
2. The extension never trusts the app's validation. Every payload is re-validated at provision **and** at connect.
3. Every XPC call has a timeout. No call waits for a tunnel connect.
4. The kill-switch policy lives only in the NE configuration (L-LC-4).
5. The extension links no AppKit, SwiftUI or Sparkle (L-EXT-5). CI greps `otool -L`.
6. The extension's secrets exist at rest only as root-owned 0600 sealed files in its sandbox container (§6.3).
7. The Sparkle EdDSA private key, the Developer ID signing identity, the Developer ID provisioning profiles and the notarization credentials never exist on a CI runner. Release artifacts are built and signed only on the dev Mac (§12.1, §12.4).
8. openvpn3 is compiled with `USE_TUN_BUILDER`, and no object from `openvpn/tun/mac/client` is linked. CI checks the symbols (§8.1).

---

## 2. Xcode project, packages, signing

### 2.1 Repository layout

**Decision:** the native app lives in this repo under `native/` until cutover (§13), so history and the issue tracker stay in one place. CI jobs are path-filtered.

```
native/
  LockPlus.xcodeproj
  Config/
    Version.xcconfig        # the ONLY version source
    Base.xcconfig           # SWIFT_VERSION=6, MACOSX_DEPLOYMENT_TARGET=15.0, ARCHS=arm64
    App.xcconfig, Tunnel.xcconfig, Signing.xcconfig
    DevStamp.xcconfig       # generated, git-ignored (see 2.6)
  App/                      # target LockPlus (SwiftUI + AppKit)
  Tunnel/                   # target LockPlusTunnel (main.swift, PacketTunnelProvider.swift)
  Packages/
    LockPlusCore/           # Foundation-only; fuzzed on macOS (-sanitize=fuzzer)
    TunnelEngine/           # NetworkExtension + Network; no UI
    WireGuardBridge/        # fork of WireGuardKit + External Build System target for libwg-go.a
    OpenVPN3Shim/           # ObjC++ over openvpn3 ClientAPI; also exposes OpenVPN3Options
  Vendor/
    openvpn3/  (submodule, pinned tag)
    openssl/   (submodule + build script; static, no-module, legacy provider built in)
    wireguard-apple/ (submodule → github.com/steiale/wireguard-apple, branch lockplus)
    patches/   (every patch we carry, applied by script, never in /tmp)
  Tools/
    leak-harness/  (Swift CLI lp-leakcheck + scenario scripts)
    release/       (archive, export, notarize, dmg, appcast, version-check)
    fuzz/          (libFuzzer targets)
  Tests/  (xcodebuild test plans: Unit, Integration)
```

### 2.2 Targets and SPM packages

| Target / package | Kind | Depends on | MUST NOT depend on |
|---|---|---|---|
| `LockPlusCore` | SPM library, modules `LPModel`, `LPParsing`, `LPWire` | Foundation | AppKit, SwiftUI, NetworkExtension, Security, CryptoKit (keeps the parsers pure and fast to fuzz; no Linux build in v2.0) |
| `TunnelEngine` | SPM library | LockPlusCore, NetworkExtension, Network, Security, os | AppKit, SwiftUI, Sparkle |
| `WireGuardBridge` | SPM library + `WireGuardGoBridge` External Build System target (`make` → `libwg-go.a`, arm64, current wireguard-go) | — | AppKit |
| `OpenVPN3Shim` | SPM library, ObjC++ (`.mm`), modules `OpenVPN3Shim` (client, compiled with `-DUSE_TUN_BUILDER`; `openvpn/tun/mac/client` excluded) and `OpenVPN3Options` (options parser only, no crypto or network) | openvpn3 headers, OpenSSL static (client module only) | AppKit |
| `LockPlus` (app) | macOS app | LockPlusCore, OpenVPN3Options, Sparkle 2.9+, ZIPFoundation (pinned) | WireGuardBridge, OpenVPN3Shim (client) |
| `LockPlusTunnel` | System extension (`SYSX`) | LockPlusCore, TunnelEngine, WireGuardBridge, OpenVPN3Shim | AppKit, SwiftUI, Sparkle, ZIPFoundation |

- **Decision:** the app links `OpenVPN3Options`, the header-only `OptionList` parser, so it can run the openvpn3 differential check at import time without the extension (§8.1).
- **Decision:** ZIPFoundation (MIT) is the one new dependency, for in-memory zip read and write. It gets an Opus/Fable review before adoption, per the CLAUDE.md "ask first" rule, and Alex must approve it.

Frameworks and rpaths (NR §4 pitfall 3):
- WireGuardBridge and OpenVPN3Shim are static libraries linked into the extension binary. There are no nested frameworks, so no rpath issues arise.
- If something must be dynamic, it goes in `LockPlusTunnel.systemextension/Contents/Frameworks` with `LD_RUNPATH_SEARCH_PATHS = @executable_path/../Frameworks`.

### 2.3 Bundle layout

```
LockPlus.app/Contents/
  MacOS/LockPlus
  Frameworks/Sparkle.framework
  Library/SystemExtensions/io.github.steiale.lockplus.mac.tunnel.systemextension/
    Contents/MacOS/io.github.steiale.lockplus.mac.tunnel
    Contents/Info.plist
    Contents/embedded.provisionprofile
  embedded.provisionprofile
```

### 2.4 Entitlements

App (`LockPlus.entitlements`):
```xml
<key>com.apple.developer.networking.networkextension</key>
<array><string>packet-tunnel-provider-systemextension</string></array>
<key>com.apple.developer.system-extension.install</key><true/>
<key>com.apple.security.application-groups</key>
<array><string>M53GHX9FAY.io.github.steiale.lockplus.mac</string></array>
<key>keychain-access-groups</key>
<array><string>M53GHX9FAY.io.github.steiale.lockplus.mac</string></array>
```

The app is hardened-runtime with no exceptions. It is not sandboxed, because it reads user-chosen files, the legacy Go data and the helper socket.

Extension (`LockPlusTunnel.entitlements`):
```xml
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.network.client</key><true/>
<key>com.apple.security.network.server</key><true/>
<key>com.apple.developer.networking.networkextension</key>
<array><string>packet-tunnel-provider-systemextension</string></array>
<key>com.apple.security.application-groups</key>
<array><string>M53GHX9FAY.io.github.steiale.lockplus.mac</string></array>
```

- Both targets use the `-systemextension` value in **every** configuration, Debug included.
  - L-EXT-6 makes dev builds Developer ID-signed, so there is no development-profile variant to maintain (NR §4 pitfall 2).
- The app group exists to satisfy the `NEMachServiceName` prefix rule.
  - **No files are shared through it:** root's and the user's group containers are different directories.

### 2.5 Info.plist keys

Extension:
```xml
<key>CFBundlePackageType</key><string>SYSX</string>
<key>CFBundleShortVersionString</key><string>$(MARKETING_VERSION)</string>
<key>CFBundleVersion</key><string>$(CURRENT_PROJECT_VERSION)</string>
<key>NetworkExtension</key><dict>
  <key>NEMachServiceName</key>
  <string>$(TeamIdentifierPrefix)io.github.steiale.lockplus.mac.tunnel.v$(CURRENT_PROJECT_VERSION)</string>
  <key>NEProviderClasses</key><dict>
    <key>com.apple.networkextension.packet-tunnel</key>
    <string>$(PRODUCT_MODULE_NAME).PacketTunnelProvider</string>
  </dict>
</dict>
<key>LSMinimumSystemVersion</key><string>15.0</string>
```

App:
- `SUFeedURL = https://steiale.github.io/lockplus/appcast.xml`
- `SUPublicEDKey`, a **new** key; the Go app's Ed25519 key is not reused.
- `SUVerifyUpdateBeforeExtraction = YES`, `SURequireSignedFeed = YES`
- `SUEnableAutomaticChecks = YES`, `SUAutomaticallyUpdate = NO`
- `LSApplicationCategoryType = public.app-category.utilities`
- `NSLocationWhenInUseUsageDescription`, used only by the optional "Add current network" button and by the app-assisted fallback if S1 fails (§10.4)
- `LSMinimumSystemVersion = 15.0`
- `LPTunnelBundleIdentifier = io.github.steiale.lockplus.mac.tunnel`

The app **reads `NEMachServiceName` from the embedded extension's Info.plist at runtime**. There is no duplicated constant.

### 2.6 Version: a single source (L-EXT-2, NR §2, NR §7)

`Config/Version.xcconfig`:
```
LP_MARKETING_VERSION = 2.0.0
LP_BUILD_NUMBER = 200000          // integer, strictly increasing per release
#include? "DevStamp.xcconfig"     // Debug only: LP_DEV_STAMP = <unix minutes>
MARKETING_VERSION = $(LP_MARKETING_VERSION)
CURRENT_PROJECT_VERSION = $(LP_BUILD_NUMBER)
```

- Debug overrides:
  - `CURRENT_PROJECT_VERSION = $(LP_BUILD_NUMBER).$(LP_DEV_STAMP)`
  - `MARKETING_VERSION = $(LP_MARKETING_VERSION).$(LP_DEV_STAMP)`
  - So **both** keys change on every dev build, and the system always sees a new extension.
- `DevStamp.xcconfig` is written by a pre-build script phase.
- `Tools/release/version-check.sh` runs in CI on every build and before the appcast is generated. It fails if any of these disagree:
  - the app and extension `CFBundleShortVersionString`/`CFBundleVersion`;
  - the `NEMachServiceName` suffix;
  - the Sparkle appcast `sparkle:version`/`shortVersionString`;
  - the git tag.

### 2.7 Provisioning

- Two Developer ID provisioning profiles, one per bundle ID, each with the NE capability, app groups, and (app only) keychain sharing and system-extension install. They are stored on the dev Mac only, never in CI (N1, §12.4).
- **Decision:** we use no Development profiles at all. NR's four profiles drop to two, because L-EXT-6 forbids development-signed NEs anyway.

---

## 3. Domain model and storage

### 3.1 Profile

```swift
// LPModel
public enum VPNProtocolKind: String, Codable, Sendable { case wireGuard = "wg", openVPN = "ovpn" }

public struct Profile: Codable, Identifiable, Sendable, Equatable {
    public let id: UUID                    // stable forever; keys every store
    public var name: ProfileName           // display only
    public let kind: VPNProtocolKind
    public var policy: NetworkPolicy
    public var auth: AuthPolicy?           // OpenVPN only
    public var notes: String               // ≤ 4 KiB
    public var summary: ProfileSummary     // derived, non-secret, for list/detail
    public var payloadRevision: UInt64     // +1 on every payload change
    public var payloadDigest: String       // hex SHA-256 of canonical payload
    public var metaRevision: UInt64        // +1 on every metadata write; mirrored to providerConfiguration "metaRev" (§3.4, N6)
    public var ownerUID: uid_t
    public var createdAt: Date, updatedAt: Date
    public var origin: ProfileOrigin       // .file(name), .zip, .qr, .editor, .migratedGo(oldName)
    public var importReport: ImportReport? // directives ignored/warned at import (§8.3)
}

public struct ProfileName: Codable, Hashable, Sendable {
    // 1…64 grapheme clusters, no C0/C1 control chars, no leading/trailing whitespace,
    // NFC-normalized; uniqueness is case- and diacritic-insensitive within the owner's profiles.
    public init(validating: String) throws
}

public struct ProfileSummary: Codable, Sendable, Equatable {
    public var endpoints: [String]        // "host:port" as written (first is primary)
    public var transport: String          // "udp" | "tcp"
    public var addresses: [String]        // WG Address / OVPN unknown until connect
    public var isFullTunnel: Bool         // WG 0/0 or ::/0; OVPN redirect-gateway in profile
    public var dnsServers: [String]
    public var usesLegacyCrypto: Bool     // §8.6
}

public struct NetworkPolicy: Codable, Sendable, Equatable {
    public var killSwitch: Bool            // full: includeAllNetworks; split: enforceRoutes
    public var allowLAN: Bool              // excludeLocalNetworks (only meaningful with killSwitch)
    public var excludeAPNs: Bool = true
    public var excludeCellularServices: Bool = true
    public var excludeDeviceCommunication: Bool = true
    public var dnsMode: DNSMode            // .tunnelOnly | .split
    public var mtuOverride: Int?           // 576…9000
    public var stayConnected: Bool         // on-demand "always" rule (replaces Go AutoReconnect)
    public var blockIPv6WithoutKillSwitch: Bool = false // v4-only full tunnels: §10.5 blackhole even with killSwitch off
}

public enum DNSMode: String, Codable, Sendable { case tunnelOnly, split }

public struct AuthPolicy: Codable, Sendable, Equatable {
    public var needsUserPass: Bool         // bare auth-user-pass
    public var appendOTP: Bool             // UI collects base password + OTP, concatenated
    public var saveCredentials: Bool       // false when profile has auth-nocache
    public var staticChallenge: StaticChallenge? // text, echo, concat
    public var needsKeyPassphrase: Bool
}
```

**Decision:** default policy for new imports:
- `killSwitch = isFullTunnel`
- `allowLAN = false`
- the three exclude flags `true`
- `dnsMode = .tunnelOnly`
- `stayConnected = false`
- `blockIPv6WithoutKillSwitch = false` (the IPv6 blackhole follows the kill switch, §10.5)

Migrated profiles take the Go app's global settings instead (§13).

### 3.2 Settings and history

```swift
public struct AppSettings: Codable, Sendable {
    public var schema = 1
    public var language: AppLanguage = .system   // applied via per-app AppleLanguages
    public var appearance: Appearance = .system
    public var menuBarShowsRates = true
    public var logLevel: LogLevel = .info        // forwarded to the extension
    public var onboardingComplete = false
    public var supportBannerDismissed = false
    public var autoConnect: AutoConnectRules = .init()
    public var newProfileDefaults: NetworkPolicy
}
public struct AutoConnectRules: Codable, Sendable {
    public var enabled = false
    public var profileID: UUID?                  // the one on-demand profile
    public var trustedSSIDs: [String] = []       // ≤ 64 entries, each ≤ 32 bytes UTF-8
    public var connectOnEthernet = false
    public var pausedUntil: Date?                // "Pause protection" (§10.4); nil = not paused
    // ssidProfileMap (SSID → specific profile) is cut from v2.0 (§21)
}
public struct HistoryEntry: Codable, Sendable, Identifiable {
    public let id: UUID                          // session ID minted by the extension
    public var profileID: UUID?, profileName: String
    public var start: Date, end: Date?
    public var rxBytes: UInt64, txBytes: UInt64
    public var endReason: SessionEndReason       // .user, .error(code), .sleep, .onDemand, .replaced
}
```

- Launch-at-login is **not** stored. It is read from `SMAppService.mainApp.status`.
- The Go settings `health_check` and `pin_interface` are dropped: the watchdog is always on and pf/-ifscope is gone. `tray_icon_style` is dropped too.
- History is capped at 500 entries.

### 3.3 Where everything lives

| Data | Location | Format | Secret? |
|---|---|---|---|
| Profile metadata | `~/Library/Application Support/io.github.steiale.lockplus.mac/profiles/<uuid>.json` (0600, dir 0700) | JSON `{"profile": Profile, "mac": hex HMAC-SHA256}` over the canonical (sorted-keys) encoding of `profile`; key = HKDF-SHA256(sealing key, info `"lockplus.metadata-mac.v1"`) | no (integrity-protected) |
| Profile payload, app copy (canonical `.conf` / canonical `.ovpn` text) | `…/profiles/<uuid>.sealed` (0600) | `AES.GCM.SealedBox.combined`, AAD = `uuid‖revision` | **yes**, sealed |
| Payload sealing key | data-protection keychain, service `io.github.steiale.lockplus.mac.payload-key`, account `v1` | 32 random bytes | yes |
| OVPN credentials, app copy | DP keychain, service `io.github.steiale.lockplus.mac.credentials`, account `<uuid>` | `CredentialRecord` binary plist | yes |
| Settings, auto-connect, history, migration marker | `…/settings.json`, `history.json`, `migration.json` (0600) | JSON | no |
| NE configuration | NE preferences, one `NETunnelProviderManager` per profile | see below | **no** |
| Payload, extension copy | extension sandbox container `Data/Library/Application Support/secrets/<uuid>.payload` (root, 0600, dir 0700) | `AES.GCM.SealedBox.combined` under the extension file key; AAD = `uuid‖"payload"‖revision` | yes, sealed |
| Credentials, extension copy | same directory, `<uuid>.cred` | sealed `CredentialRecord`; AAD = `uuid‖"cred"` | yes, sealed |
| Extension file key | S4 primary: `secrets/filekey.wrapped` = the file key HPKE-sealed to a CryptoKit Secure Enclave P-256 key-agreement key, whose wrapped `dataRepresentation` is in `secrets/se.key`. Fallback: `secrets/filekey.raw` (32 bytes) | binary | yes (root 0600) |
| Extension runtime state (session ring, auth backoff, provision index) | extension sandbox container `Data/Library/Application Support/state.plist` (root, 0600) | plist, with a `schema` field; a newer schema than the running build understands is discarded and rebuilt by reconcile (needed for §4.6 rollbacks) | no |

The container is `/private/var/root/Library/Containers/io.github.steiale.lockplus.mac.tunnel/`. It is created by the sandbox for the root extension, so no other path or entitlement is involved.

**Device-bound data (Time Machine / Migration Assistant).** The sealing key is `…ThisDeviceOnly`, so it is not restored to a new Mac. The extension's file key does not move either: it is root-container data, and the Secure Enclave wrap is device-bound. After a restore to a new Mac the profiles are therefore **unrecoverable from the sealed files**. This is deliberate (a backup must not carry usable VPN keys) and handled in §6.8.

- The app data directory is named after the **bundle ID**, never `lockplus`.
  - So no Go-app cask `zap` stanza can ever match it (L-DIST-1, the bb50f10 incident).
- `providerConfiguration` (≤ 2 KiB, enforced):
  ```swift
  ["v": 1, "profileID": "<uuid>", "kind": "wg"|"ovpn", "revision": 7, "metaRev": 12, "ownerUID": 501,
   "dnsMode": "tunnelOnly", "mtu": 1420?, "blockIPv6": false, "auth": ["interactive": true]]
  ```
  - `metaRev` is `Profile.metaRevision` at the last manager save; it is the replay reference for §3.4 (N6).
- Other `NETunnelProviderProtocol` fields:
  - `providerBundleIdentifier` is the extension ID;
  - `serverAddress` is the primary endpoint, for System Settings display;
  - `passwordReference` and `username` stay `nil`, because the extension cannot read `passwordReference` (L-CRED-1).
- `includeAllNetworks`, `enforceRoutes`, `excludeLocalNetworks` and the other exclude flags are set from `NetworkPolicy` (§10).
- `disconnectOnSleep = false`.
- `localizedDescription` is `profile.name`.

### 3.4 ProfileStore (app)

```swift
public protocol ProfileStore: Sendable {
    func list() async throws -> [Profile]                      // owner's profiles only
    func payload(for id: UUID) async throws -> SecretBytes     // unseals; caller zeroes
    func create(_ draft: ProfileDraft) async throws -> Profile // validates, seals, saves NE manager, provisions ext
    func updatePayload(_ id: UUID, _ text: SecretBytes) async throws -> Profile
    func updatePolicy(_ id: UUID, _ policy: NetworkPolicy) async throws // throws .mustBeDisconnected (L-KS-2)
    func rename(_ id: UUID, to: ProfileName) async throws       // metadata + localizedDescription only
    func delete(_ id: UUID) async throws
    func reconcile() async                                      // see 6.4
}
```

- It is implemented as an `actor FileProfileStore`. All I/O is off the main actor (L-CRED-1).
- Writes are atomic: temp file in the same dir, `F_FULLFSYNC`, `rename`.
- Corrupt JSON is moved to `*.corrupt.<UTC>` and logged, never fatal. This is ported from Go `SettingsStore.Load`.
- **Metadata integrity (A1):** every metadata write recomputes the HMAC (§3.3); every load verifies it in constant time. On mismatch, the file is moved to `*.tampered.<UTC>`. The profile is shown as "Settings were changed outside LockPlus", and its NE manager is **not** re-saved and reconcile skips it. The user can restore the policy from the NE manager (the system's copy), re-import, or delete. The HMAC covers `policy`, `auth`, `ownerUID`, `payloadRevision`, `payloadDigest` and `metaRevision`, i.e. the whole `Profile`.
- **Replay (N6):** an HMAC alone does not stop same-user code from restoring an **older, validly MAC'd** metadata file (and its matching `.sealed` file), e.g. one from before the user turned the kill switch on. The reference copy is the NE manager, which same-user code cannot write: every manager save writes `providerConfiguration.metaRev = metaRevision` and `revision = payloadRevision`. Before reconcile or any save writes NE preferences or provisions the extension from metadata:
  - metadata `metaRevision` **lower** than the manager's `metaRev`, or `payloadRevision` lower than the manager's `revision` → replay: handled exactly like an HMAC mismatch (`*.tampered.<UTC>`, NE manager untouched, nothing provisioned);
  - equal `metaRevision` but a policy that differs from the manager's protocol flags → also treated as tampering (a legitimate write always bumps the counter);
  - higher → a legitimate write whose manager save didn't complete; reconcile saves it.
  - No manager exists (e.g. the user removed the VPN in System Settings) → no reference, so the profile is shown as "Not installed" and re-created only by an explicit user action that shows the policy being saved.
  - The extension's provision index also refuses a `provisionProfile` with a revision lower than the one it holds, except after `wipeAllSecrets` or a §4.6 reinstall.
- The store keeps a **single cached `[UUID: NETunnelProviderManager]`**. `loadAllFromPreferences` is called once at launch and again after a `NEVPNConfigurationChange` notification; managers are never reloaded per call (NR §4 practices).

### 3.5 Import caps (ported, NR §3 "Security posture")

| Input | Cap |
|---|---|
| single profile file | 1 MiB raw `.ovpn` (matches `maxOVPNSize`; comments and ignored directives are dropped before the canonical cap of **256 KiB** = openvpn3 `MAX_PROFILE_SIZE`, §8.1), 64 KiB (`.conf`) |
| zip | 500 profile entries, 10 MiB decompressed per entry (`LimitReader` semantics), 100 MiB total; read in memory only |
| QR image | 20 MiB, 8000×8000 px (checked from `CGImageSource` properties before decoding) |
| drag-drop | the same as a file; directories are rejected |

Entry names go through `sanitizeProfileName` (a port of `sanitizeTunnelName`) and are used **only** as display names.

---

## 4. System extension lifecycle

### 4.1 SystemExtensionManager

```swift
@MainActor @Observable
final class SystemExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    enum State: Equatable {
        case unknown, activating, needsUserApproval, needsReboot, ready(version: String)
        case failed(ExtensionFailure)           // terminal until user acts
        case deactivating, uninstalled
    }
    private(set) var state: State = .unknown
    func activate() async                       // idempotent; called on every launch (L-EXT-2); quiesces first (§4.2)
    func deactivate() async throws              // uninstall path (L-EXT-4)
    func reinstall() async throws               // user-initiated rollback path (§4.6)
    var machServiceName: String { get }         // read from embedded ext Info.plist
}
```

### 4.2 Activation on every launch (L-EXT-1, L-EXT-2)

`OSSystemExtensionRequestDelegate.request(_:actionForReplacingExtension:withExtension:)` is **synchronous**: it must return a `ReplacementAction` immediately and cannot await a tunnel stop. All quiescing therefore happens **before** any activation request is submitted.

1. At `applicationDidFinishLaunching`, run `activate()` once.
2. **Preflight:** submit `OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier:queue:)` and wait for `request(_:foundProperties:)` (5 s timeout; on timeout, treat it as "unknown" and go to step 4 without quiescing, logged).
   - `isAwaitingUserApproval` on any entry → show the approval **banner** rather than a new modal.
   - Find the **enabled** entry (`isEnabled && !isUninstalling`) and compare its `(bundleShortVersion, bundleVersion)` numerically with the embedded extension's Info.plist.
     - No enabled entry, or equal versions → step 4.
     - Enabled version **lower** than embedded (an update is pending) → step 3.
     - Enabled version **higher** than embedded (the user installed an older app) → do **not** submit. `state = .failed(.olderAppThanExtension)`. The UI offers "Reinstall tunnel component" (§4.6). The higher extension keeps running and keeps working with its own per-version Mach name, but this app can't talk to it, so the UI is read-only (status via `NEVPNStatus` only).
3. **Quiesce (only when a replacement is pending):** for every owned manager whose status is not `.disconnected`/`.invalid`, or that has `isOnDemandEnabled`:
   1. write `pendingResume = {profileID, onDemandEnabledIDs: [UUID], reason: .extensionUpdate}` to `settings.json` (unless §12.3 already wrote one). `onDemandEnabledIDs` lists **every** owned manager that had `isOnDemandEnabled` (the auto profile, `stayConnected` profiles, and the §10.1.1 E1 keep-alive rule), not only the auto profile;
   2. set `isOnDemandEnabled = false` and save;
   3. `stopVPNTunnel()` and await `.disconnected` (15 s; on timeout continue, logged);
   4. show "Updating tunnel component…" in the menu bar and window.
   - This covers every way a new app can arrive with the old extension still running: Sparkle (§12.3 has usually quiesced already, so this is a no-op), a drag-replace in Finder, and `brew upgrade` while the app was closed and the tunnel was up (on-demand or connected). In the last two cases the old extension has kept protecting the user until this launch. With a kill-switch profile, the Mac is unprotected from step 3.3 until the resume in step 6. That window is the price of L-KS-3 and is shown: "Updating — not protected for a moment".
4. Submit `OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier:queue: .main)`.
5. Handle the delegate callbacks (table below).
6. On `.completed` with a `pendingResume`, run `UpdateCoordinator.resumeAfterUpdate()` (§12.3 step 4).

| Callback / result | Action |
|---|---|
| `actionForReplacingExtension(existing, ext)` | **Pure compare, no side effects.** Compare `(CFBundleShortVersionString, CFBundleVersion)` numerically. Higher or equal → `.replace` (equal: dev rebuilds with the same stamp are harmless). **Lower** → `.cancel` and `state = .failed(.downgradeRefused)`; this cannot normally happen because step 2 does not submit in that case. The only exception is `reinstall()` (§4.6), which deactivates first, so no replacement is involved. |
| `requestNeedsUserApproval` | `state = .needsUserApproval`. Show **one** sheet: an explanation plus "Open System Settings", which opens `x-apple.systempreferences:com.apple.LoginItems-Settings.extension`. Keep the request alive; never resubmit. |
| `didFinishWithResult(.completed)` | `state = .ready`, then the XPC `hello` (§5) and `ProfileStore.reconcile()`. |
| `didFinishWithResult(.willCompleteAfterReboot)` | `state = .needsReboot`. Show one dialog, "Restart to finish installing", with no retry. |
| `didFailWithError` `.unsupportedParentBundleLocation` | Dialog: "Move LockPlus to Applications", with a button that calls `NSWorkspace` to reveal it. |
| `.missingEntitlement`, `.codeSignatureInvalid`, `.validationFailed`, `.invalidSystemExtension`, `.extensionMissingIdentifier`, `.unknownExtensionCategory` | `failed(.broken(code))`: "This copy of LockPlus is damaged. Reinstall." Include a diagnostics export button. |
| `.forbiddenBySystemPolicy` | `failed(.managed)`: "Your organization blocks this extension." |
| `.requestCanceled`, `.requestSuperseded` | Ignore. The state stays as it was. |
| `.authorizationRequired` | Only on deactivate: "Administrator approval required", user-initiated retry. |
| `.extensionNotFound` | Bundle damaged (as above). |

- **No automatic retries anywhere.** A "Try again" button exists only in the failure UI and is user-initiated.
- Settings › Advanced › "Reinstall tunnel component…" is in **release** builds (§4.6).
- Debug menu (DEBUG builds and `⌥`-click on About):
  - Activate;
  - Deactivate;
  - "Deactivate + Activate" (L-EXT-6);
  - "Show extension log".

### 4.3 Replacement policy

- The system replaces the extension when the app requests activation of a bundle whose versions differ. We answer `.replace` for higher or equal versions. The tunnel has **already** been quiesced by the §4.2 preflight before the request was submitted (L-EXT-3, L-KS-3); the delegate itself does nothing but compare.
- Edge case: the system extension is enabled but `propertiesRequest` timed out, so step 3 was skipped. The replacement then happens with the tunnel possibly up. The FB17032197 XPC breakage is avoided by the per-version Mach name. The tunnel is torn down by the replacement, and on-demand restarts it on the new extension. S5 records what the user sees in this case.
- `NEMachServiceName` includes `CURRENT_PROJECT_VERSION`, so the old extension's listener and the new app never talk across versions (FB17032197). The app connects to the name in **its own** embedded extension's plist. Before replacement completes, that lookup fails, and the app shows "Updating tunnel component…".
- **Assumption A-EXT-1:** a per-version Mach name has no side effects beyond a launchd registration per version. Spike S5 validates this. **Fallback:** a fixed name plus the mandatory stop-before-replace rule, which already prevents the FB17032197 scenario.

### 4.4 Uninstall (L-EXT-4)

The Settings › Advanced › "Uninstall LockPlus…" sequence:
1. Authenticate with `LAContext`, then confirm.
2. For every manager: `isOnDemandEnabled = false`, save, `stopVPNTunnel()`, wait for `.disconnected` (10 s timeout).
3. XPC `wipeAllSecrets(ownerUID)`, which makes the extension delete this UID's sealed secret files and state entries. When the last UID is wiped, it also deletes the file key and the Secure Enclave key blob. This step matters: deactivation does not reliably delete the extension's sandbox container (TBD-by-S5), so leftover sealed files would otherwise outlive the app. Errors are recorded but not fatal.
4. `removeFromPreferences()` for each owned manager.
5. Delete the DP keychain items (payload key, credentials).
6. `deactivationRequest`. This may require admin approval or a reboot; both are shown.
7. Ask "Also delete your profiles and history?" before removing App Support (default **No**).
8. `SMAppService.mainApp.unregister()` and the §10.4 resume agent's `unregister()`, if registered.
9. Move the app to the Trash with `NSWorkspace.recycle`, then quit.

The cask's `uninstall` runs the app headless with `--uninstall-system-components` (steps 2–6, no windows, 60 s timeout), followed by `quit`.
- "Headless" is best effort. `deactivationRequest` may show the system's admin-authorization dialog, or end in `.willCompleteAfterReboot`; `brew uninstall` cannot answer either. The stanza therefore keeps `must_succeed: false`. On timeout, or when authorization is needed and nobody answers, the extension stays installed until the user removes it in System Settings › General › Login Items & Extensions, or until a reboot completes it.
- The cask `caveats` and the README say this plainly: "If macOS asks for an administrator password while uninstalling, that's the tunnel component being removed. If you dismiss it, remove LockPlus's network extension in System Settings."

### 4.5 Coexistence with the Go app

Detection (`LegacyAppDetector`, app side; the extension cannot see pf):
1. `/Library/LaunchDaemons/io.github.steiale.lockplus.helper.plist` exists → helper installed.
2. Connect to `/var/run/lockplus/lockplus.sock` (0600, owned by this user, per `internal/ipc/transport_unix.go`) with a 2 s timeout and send the Go IPC status request.
   - The response tells us whether a tunnel is active or the kill switch is enabled. We send a read-only call only.
   - Note: the Go IPC authenticates the peer by **uid only** (`LOCAL_PEERCRED`, `internal/ipc/peercred_darwin.go`, `verifyPeerUID`), not by code signature. That is why the native app can call it at all, and it is also why §13.3's `Uninstall` RPC is callable by any same-user process.
3. `NSRunningApplication` with bundle ID `io.github.steiale.lockplus` → the Go GUI is running.
4. `/Library/Application Support/lockplus/dns-journal.json` or `pf-was-enabled` exists → state is left behind.
   - `pf-was-enabled` is written when the Go helper first loads its pf anchor and removed on every clean teardown (`internal/firewall/darwin.go`, `Apply`/`teardownLocked`). Its presence therefore means "the Go kill switch's pf rules were active and never torn down". Checking it needs no root: `stat` on a world-readable directory. It is the non-root signal for a **crashed helper with pf loaded**, since `pfctl` itself needs root.

Policy:

| Finding | Behaviour |
|---|---|
| Helper reports an active tunnel or the kill switch on (pf anchor `com.apple/wireguide` loaded) | **Refuse to connect.** Dialog: "Disconnect in the old LockPlus and turn off its kill switch first", plus a button that opens the Go app. |
| Helper installed but idle | Allow connecting, with a persistent banner: "The old LockPlus helper is still installed. Run its uninstaller (§13.3)." |
| Helper installed but **unreachable**, and `pf-was-enabled` exists | The helper probably crashed with its kill switch loaded, so pf may block our tunnel's traffic and the connect would fail without explanation. Allow connecting (pf may be gone), but show a warning before connecting: "The old LockPlus may have left its firewall on." The helper's LaunchDaemon has `KeepAlive=true`, and a restarted helper's `RecoverStaleState` flushes the anchors. An unreachable helper with the marker present therefore means it is crash-looping or was booted out. Offer to open the old app or to restart the Mac (a reboot clears pf rules), and link the §13.3 uninstaller. If the connect then fails with `.connectTimeout`/`.peerUnreachable`, the error banner repeats this hint. |
| Helper installed but unreachable, no `pf-was-enabled` | As "idle". |
| Leftover DNS journal or `pf-was-enabled`, no helper | Banner with instructions (restart, or reinstall and run the Go app's v1.2.0 uninstaller). We never touch root state ourselves. |

### 4.6 Reinstall tunnel component (user-initiated rollback, M2)

Automatic replacement never downgrades (§4.3). A legitimate rollback (the user installs N-1 because N broke something) therefore needs an explicit path. It is offered in Settings › Advanced › "Reinstall tunnel component…" and in the `.failed(.olderAppThanExtension)` / `.failed(.downgradeRefused)` UI.

1. Confirmation sheet: "This removes the installed tunnel component (version X) and installs the one bundled with this app (version Y). VPN connections stop. macOS may ask for an administrator password." Buttons Cancel / Reinstall; **Cancel** is the default. LAContext is required, because a downgrade is security-relevant.
2. Quiesce as in §4.2 step 3, with `pendingResume.reason = .reinstall`.
3. `deactivationRequest`, then await the result. `.willCompleteAfterReboot` → "Restart to finish", and the app resumes at step 4 on the next launch (a marker in `settings.json`).
4. `activationRequest` for the embedded extension. Since nothing is enabled, no replacement callback occurs. The normal approval rules (§4.2) apply.
5. On `.completed`: `hello`, then `reconcile()`, which re-provisions every profile; the extension's `state.plist` with a newer schema is discarded (§3.3). Then resume.
- Never automatic, never offered by a background path, and logged at `.notice` with both versions.
- S5 confirms that deactivate → activate of a *lower* version works without a reboot on 15 and 27 (TBD-by-S5). If it needs a reboot, step 3's path is the normal one.

---

## 5. App ↔ extension IPC

### 5.1 Channel choice

- **XPC** over `NEMachServiceName` is used for everything: provisioning, auth, status detail, stats, logs, diagnostics.
  - It works while the tunnel is down, because launchd starts the extension on demand when the Mach service is looked up.
- **`sendProviderMessage`** is used for nothing in production. It needs a running provider instance and has no peer validation of its own beyond NE.
  - We keep one debug-only `ping` through it to triage "XPC unreachable but tunnel up" (§17, S5).
- **Start, stop and status** go through `NETunnelProviderSession.startVPNTunnel(options:)`, `stopVPNTunnel()`, `NEVPNStatusDidChange` and `fetchLastDisconnectError`. A slow connect is therefore never an XPC call that can time out (L-LC-3).

### 5.2 Protocol definition

Payloads are `Codable` structs encoded as binary property lists and carried as `Data`. `LPWire` owns the encode and decode, so size checks happen **before** decoding and versioning is field-additive.

```swift
// LPWire (LockPlusCore) — shared by app and extension
public let LPWireVersion: UInt16 = 1

@objc public protocol LPTunnelServiceXPC {
    func hello(_ req: Data, reply: @escaping (Data?, Data?) -> Void)                // ClientHello → ServerHello
    func provisionProfile(_ req: Data, reply: @escaping (Data?) -> Void)            // ProvisionRequest → LPError?
    func updateCredentials(_ req: Data, reply: @escaping (Data?) -> Void)
    func removeProfile(_ req: Data, reply: @escaping (Data?) -> Void)
    func listProvisioned(_ req: Data, reply: @escaping (Data?, Data?) -> Void)
    func wipeAllSecrets(_ req: Data, reply: @escaping (Data?) -> Void)
    func validateProfile(_ req: Data, reply: @escaping (Data?, Data?) -> Void)      // engine-side re-check
    func tunnelSnapshot(_ req: Data, reply: @escaping (Data?, Data?) -> Void)       // state, endpoint, addrs, cipher
    func statistics(_ req: Data, reply: @escaping (Data?, Data?) -> Void)
    func pendingAuthPrompt(_ req: Data, reply: @escaping (Data?, Data?) -> Void)
    func answerAuth(_ req: Data, reply: @escaping (Data?) -> Void)
    func cancelAuth(_ req: Data, reply: @escaping (Data?) -> Void)
    func recentLogs(_ req: Data, reply: @escaping (Data?, Data?) -> Void)
    func sessionSummaries(_ req: Data, reply: @escaping (Data?, Data?) -> Void)
    func measureLatency(_ req: Data, reply: @escaping (Data?, Data?) -> Void)       // profile endpoints only
    func setLogLevel(_ req: Data, reply: @escaping (Data?) -> Void)
}

@objc public protocol LPAppCallbackXPC {          // exported by the app on the same connection
    func tunnelEvent(_ event: Data)                // fire-and-forget: status detail, authRequired, sessionEnded
}

public struct ClientHello: Codable { var wire: UInt16; var appVersion: String; var appBuild: String }
public struct ServerHello: Codable {
    var wire: UInt16; var extVersion: String; var extBuild: String
    var capabilities: Set<Capability>   // .openVPN, .wireGuard, .keyPassphrase (DoH/DoT: §21)
}
public struct ProvisionRequest: Codable {
    var profileID: UUID; var kind: VPNProtocolKind; var revision: UInt64
    var payload: Data                    // canonical text, ≤ 256 KiB (§8.1)
    var credentials: CredentialRecord?   // ≤ 4 KiB encoded
}
public struct CredentialRecord: Codable {
    var v: UInt8 = 1; var username: Data?; var password: Data?; var keyPassphrase: Data?
}  // username ≤ 512 B, password ≤ 1024 B, passphrase ≤ 1024 B; no CR/LF/NUL in username/password
public struct AuthPrompt: Codable {
    var promptID: UUID; var profileID: UUID; var kind: AuthKind  // .userPass, .staticChallenge, .dynamicChallenge, .keyPassphrase
    var challengeText: String?           // ≤ 1 KiB, server-controlled, rendered as plain text only
    var echo: Bool; var lockedUsername: String?; var reason: AuthReason // .initial, .rejected, .reconnect
    var savedUsername: String?
}
public struct AuthAnswer: Codable {
    var promptID: UUID; var username: Data?; var password: Data?; var response: Data?; var save: Bool
}
```

Size limits are enforced in `LPWire.decode(_:max:)`:

| Message | Limit |
|---|---|
| `hello` | 4 KiB |
| `provision`, `validateProfile` | 300 KiB |
| `answerAuth` | 8 KiB |
| `recentLogs` reply | 1000 lines, 256 KiB |
| `sessionSummaries` reply | 100 entries |
| others | 16 KiB |

Oversized messages are rejected with `.payloadTooLarge` and never decoded.

**Versioning:**
- `LPWireVersion` bumps only on an incompatible change; additive fields are optional.
- `hello` is always the first call on a connection. A mismatch yields `.versionMismatch`, and the app calls `activate()`, which replaces the extension.
- With per-version Mach names, a mismatch should never happen in practice. The check is a defence.

### 5.3 Peer code-signature validation (both ends)

Requirement strings, compiled in from `Signing.xcconfig`:
```
DEVID   = anchor apple generic
          and certificate 1[field.1.2.840.113635.100.6.2.6] exists       // Developer ID CA
          and certificate leaf[field.1.2.840.113635.100.6.1.13] exists   // Developer ID Application leaf
          and certificate leaf[subject.OU] = "M53GHX9FAY"
APP_REQ = $(DEVID) and identifier "io.github.steiale.lockplus.mac"
EXT_REQ = $(DEVID) and identifier "io.github.steiale.lockplus.mac.tunnel"
```

- The requirement pins **Developer ID only**, with the team ID quoted. Apple Development, Mac App Distribution and ad-hoc signatures all fail by design. L-EXT-6 makes every dev build Developer ID-signed, so nothing legitimate is lost.
- Extension:
  - The listener calls `setConnectionCodeSigningRequirement(APP_REQ)` (macOS 13+) **before `resume()`**. This is the primary check.
  - In `listener(_:shouldAcceptNewConnection:)` it also calls `conn.setCodeSigningRequirement(APP_REQ)` as belt and braces, and records `conn.effectiveUserIdentifier` for ownership checks.
  - **Enforcement timing:** the check runs when the **first message** arrives on the connection, not at accept time (forum 760287). Rejected peers are invalidated before any handler runs. Rule: `shouldAcceptNewConnection` does no work and allocates nothing beyond the connection object. All per-connection state (ownership, auth subscriptions) is created lazily inside the first handler, `hello`, which by then has passed the check.
  - *Reviewed: "pre-check the audit token in `shouldAcceptNewConnection`" was not adopted.* `NSXPCConnection.auditToken` is not public API (it is SPI used through KVC), and the public `processIdentifier` is PID-reuse-racy, so neither is a sound pre-check. The lazy-state rule above gets the same effect, namely that no work is done for an unvalidated peer, using only public API.
- App: `conn.setCodeSigningRequirement(EXT_REQ)` before `resume()`. The app's exported `LPAppCallbackXPC` is only reachable over this already-validated connection.
- Test: a team-signed binary with a different identifier, an Apple Development-signed copy of the app, and an unsigned binary all get `NSXPCConnectionInvalid` before any handler log line (§15.6).

### 5.4 Timeouts, ownership and rate limits

```swift
actor TunnelServiceClient {
    func call<Req: Encodable, Resp: Decodable>(
        _ method: Method, _ req: Req, timeout: Duration
    ) async throws(LPError) -> Resp
}
```

- Each call uses `remoteObjectProxyWithErrorHandler`, a `CheckedContinuation` guarded by a one-shot flag, and a `Task.sleep(for: timeout)` race.
  - On timeout it throws `.timeout(method)` and **ignores** the late reply.
- Per-method timeouts:
  - `hello` 3 s
  - `tunnelSnapshot`, `statistics`, `pendingAuthPrompt` 2 s
  - `provision`, `remove`, `wipe` 10 s
  - `validateProfile` 5 s
  - `answerAuth` 5 s
  - `recentLogs` 3 s
  - `measureLatency` 6 s
- **Liveness rule (L-LC-3):** only `invalidationHandler` counts as "extension gone".
  - A timeout yields `.extensionBusy`, which the UI shows only after 3 consecutive timeouts, as a non-blocking indicator.
  - No timeout ever triggers reinstall, reactivation or a "dead extension" dialog. This is the 7a55ba6/aa46660 lesson.
- `interruptionHandler` reconnects lazily on the next call.
- Extension side: every handler replies on every path. Handlers never await the engine without their own internal deadline, which is 1 s below the client's.
- Ownership: every profile-scoped request carries `profileID`. The extension looks up `ownerUID` in its provision index and rejects a mismatch with the connection's `effectiveUserIdentifier` (`.notOwner`).
- No rate limiting in v2.0 (cut, §21). Callers are signature-validated same-team code. Flooding by the app itself would be a bug, caught in testing. `.rateLimited` stays reserved in the error enum.

### 5.5 Error model

```swift
public struct LPError: Error, Codable, Sendable {
    public var code: LPErrorCode
    public var detail: String?        // ≤ 512 chars, never contains secrets or server-controlled text
}
public enum LPErrorCode: Int, Codable, Sendable {
    // transport
    case timeout = 1, extensionUnavailable, extensionBusy, versionMismatch, unauthorizedPeer,
         payloadTooLarge, malformedRequest, rateLimited /* reserved */, notOwner
    // profile
    case profileNotProvisioned = 100, profileInvalid, profileRevisionStale, unsupportedDirective
    // tunnel (also used as NSError codes for cancelTunnelWithError, domain "io.github.steiale.lockplus.tunnel")
    case authFailed = 200, authRequired, authTimedOut, webAuthUnsupported, keyPassphraseRequired,
         connectTimeout, peerUnreachable, dnsResolutionFailed, engineFatal, tunDeviceFailed,
         networkSettingsFailed, legacyCryptoUnavailable, serverIdentityMismatch, conflictingVPN,
         secretStoreUnavailable, blockedAfterFailure
}
```

- The extension's `cancelTunnelWithError(NSError(domain: LPTunnelErrorDomain, code: …))` carries only the code plus a non-secret `detail` in `userInfo["lp.detail"]`.
- The app localizes every message from the code; the extension has no localization (it runs as root, in an unknown locale).
- **Assumption A-ERR-1:** `fetchLastDisconnectError` returns the provider's NSError with its domain, code and userInfo intact. Spike S12 validates this.
  - **Fallback:** the extension also stores `lastError` per profile in its state file, and the app reads it via `tunnelSnapshot`.

---

## 6. Credentials: the two-store design (L-CRED-1)

### 6.1 Ownership matrix

| Secret | App DP keychain | Extension container store (§6.3) | Written by | When |
|---|---|---|---|---|
| Payload sealing key | ✔ | — | app | first launch |
| Extension file key | — | ✔ `secrets/filekey.*` | extension | first provision |
| Payload (keys inside `.conf`/`.ovpn`) | sealed file (key in DP keychain) | ✔ `secrets/<uuid>.payload` | app; extension via `provisionProfile` | import, edit, reconcile |
| OVPN username/password/key passphrase | ✔ `…credentials/<uuid>` | ✔ `secrets/<uuid>.cred` | app; extension via provision/`updateCredentials` | user saves, or "save" ticked in a prompt |
| OTP, SC/CRV1 responses, `auth-token` | never | never (memory only, zeroed) | — | per prompt |

- The app **never** reads the extension's copy, and the extension never reads the app's.
- The app's copy is the **source of truth**. The extension's copy is a cache that `reconcile()` can always rebuild.

### 6.2 App store

```swift
public protocol CredentialStore: Sendable {
    func load(_ id: UUID) async throws -> CredentialRecord?     // nil = not found (distinct from error)
    func save(_ id: UUID, _ rec: CredentialRecord) async throws
    func delete(_ id: UUID) async throws                         // not-found is success
}
actor DataProtectionCredentialStore: CredentialStore { … }
```

The query attributes:
- `kSecUseDataProtectionKeychain: true`
- `kSecAttrAccessGroup: "M53GHX9FAY.io.github.steiale.lockplus.mac"`
- `kSecClass: kSecClassGenericPassword`, service as in §3.3, account `uuid.uuidString`
- `kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- `kSecAttrSynchronizable: false`

Behaviour:
- `save` is `SecItemUpdate`, falling back to `SecItemAdd` on `errSecItemNotFound`. Values are raw `Data`; there is no text encoding at all (the b64:/hex lesson).
- Calls run on the actor's executor, never on the main thread.

### 6.3 Extension store (root-owned container files)

Why not the System keychain (draft 1's design):
- An NE system extension is effectively a daemon, so it cannot use the data-protection keychain. A **sandboxed** one hits sandbox violations on `/Library/Keychains/System.keychain` (DTS, forum 672456; the same failure was reported in 680013).
- Root's *default* keychain is not automatically the System keychain. Targeting it needs `SecKeychainOpen`/`SecKeychainSetPreferenceDomain` + `kSecUseKeychain`, all deprecated and unverified from a sandbox.
- `SecAccess`/`SecTrustedApplicationCreateFromPath` are deprecated, and there is no supported API to set partition lists (DTS, 98182: "there's no supported way").
- Draft 1's fallback ("sealed file, key in the System keychain") has the same blocker.
- DTS does say a sysex *can* use the file-based System keychain with work (824202: "That's what I'd use, possibly with a scrambling layer"). So it stays an **optional upgrade** that S4 may adopt, not the baseline.

```swift
actor ContainerSecretStore {               // TunnelEngine
    func put(_ kind: SecretKind, _ id: UUID, ownerUID: uid_t, _ bytes: SecretBytes) throws(LPError)
    func get(_ kind: SecretKind, _ id: UUID) throws(LPError) -> SecretBytes?
    func delete(_ kind: SecretKind, _ id: UUID) throws(LPError)
    func deleteAll(ownerUID: uid_t) throws(LPError)
}
```

Layout and rules:
- The directory is `<container>/Data/Library/Application Support/secrets/` (§3.3). At first use the store creates it with mode 0700 and verifies `lstat` owner `0`, mode `0700` and not a symlink. If verification fails, the store refuses to operate (`.secretStoreUnavailable`).
- Files are written with `open(O_CREAT|O_EXCL|O_NOFOLLOW, 0600)` to a temp name, `F_FULLFSYNC`, then `rename`. Reads use `O_NOFOLLOW` and check owner and mode via `fstat`.
- Each file is `AES.GCM.SealedBox.combined` under the 256-bit **file key**, with AAD binding the UUID, kind and revision (§3.3). A file swapped between profiles fails authentication.
- The **file key** is generated once with `SecRandomCopyBytes`. How it is kept at rest is S4's question:
  1. **Primary candidate: Secure Enclave wrap.** Create `SecureEnclave.P256.KeyAgreement.PrivateKey` (CryptoKit). Store its wrapped `dataRepresentation` in `se.key` and the file key HPKE-sealed to its public key in `filekey.wrapped`. Quinn (forum 804612) reports this works from a daemon via CryptoKit but has "no official answer" on support. Default accessibility is `AfterFirstUnlockThisDeviceOnly`, so unwrapping **before the first user login after boot** fails with -25308. **Decision:** we accept that rather than use the deprecated `kSecAttrAccessibleAlways`. A pre-login on-demand start fails with `.secretStoreUnavailable` and on-demand retries after login. The Go app never connected before login either.
  2. **Fallback: plain root file.** `filekey.raw`, 0600 root. This is equivalent to "root ownership only".
  3. **Optional upgrade (S4, not v2.0 baseline):** the file key in the System keychain, only if S4 shows it works from the sandboxed extension without temporary-exception entitlements and without prompts.
- **What this protects, and what it doesn't.** Root ownership is the real boundary: it defeats A1 (same-user malware) and non-admin users (A2). The Secure Enclave wrap adds only that copied files, disk images and backups are useless off this Mac. It does **not** stop a live root process on this Mac, which can use the wrapped key the same way we do. **Admin users are out of scope** (§1.3 A2), and this is stated in the user documentation.
- The provision index records `ownerUID` per UUID, and `deleteAll(ownerUID:)` deletes exactly those files.
- The app → XPC → extension hand-off is unchanged (§6.4). The app never reads these files, and the extension never reads the app's keychain.
- **Assumption A-KC-1 (revised):** a sandboxed root system extension can create, read, rename and delete files in its own container on macOS 15/26/27, and the container survives extension replacement. TBD-by-S4. Container access is the sandbox's basic contract, so the risk is low. A-KC-2 (Secure Enclave wrap from the sysex, including after replacement and after reboot before and after login) is TBD-by-S4, with fallback 2.

### 6.4 Hand-off and reconcile

- **Provision:** on create or edit, the app seals locally, then calls `provisionProfile(id, revision, payload, creds?)`. The extension then:
  1. checks ownership;
  2. **re-validates** the payload (§8.1/§9.1);
  3. stores the payload and credentials;
  4. records `(id, revision, ownerUID, digest)` in its provision index;
  5. replies.
- **Reconcile:** runs after every successful `hello`.
  1. The app sends `listProvisioned(ownerUID)` and gets back `[(id, revision, digest)]`.
  2. For every local profile whose revision or digest differs, or that is missing, it re-provisions.
  3. For every extension entry with no local profile, it calls `removeProfile`.
  4. Deletions that fail are queued in `pendingRemovals` (in `settings.json`) and retried on the next reconcile.
- **Connect when not provisioned:** the extension fails `startTunnel` with `.profileNotProvisioned`. The app catches this, reconciles, and retries **once**, with user-visible progress.
- **Stale revision:** `providerConfiguration.revision` is greater than the provisioned revision → `.profileRevisionStale`, handled the same way.

### 6.5 Memory hygiene

```swift
public final class SecretBytes: @unchecked Sendable {   // LPModel
    private let buf: UnsafeMutableRawBufferPointer       // allocated, mlock()'d best-effort
    public init(copying: some ContiguousBytes); public init(count: Int)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    deinit { memset_s(buf.baseAddress, buf.count, 0, buf.count); munlock(…); buf.deallocate() }
    // description / debugDescription / customMirror → "<redacted>"; not Codable; not Equatable
}
```

Rules:
- Secrets stay in `SecretBytes` from keychain read to engine call.
- `Data`/`String` copies are unavoidable at the XPC and SwiftUI `SecureField` boundaries. They are scoped to the smallest block, never captured in long-lived closures, and never stored in `@Observable` state after submit (prompt view models clear their fields on submit or dismiss).
- C++ side: the shim copies into `std::string`, calls `provide_creds`, then zeroes the buffer with `OPENSSL_cleanse`. openvpn3's internal copies are out of our control; this is documented.
- Crash reports:
  - no `fatalError` messages that interpolate values;
  - `SecretBytes` has no reflection;
  - the extension sets no `NSException` reasons containing data.
- Logs: §14. A unit test greps the built binaries' string tables for format strings containing `password`/`key` interpolations, and a SwiftLint custom rule forbids `\(…password…)` in `Logger` calls.

### 6.6 Rotation, deletion, rename

- **Rotation:** the user edits credentials in Profile › Authentication.
  1. `CredentialStore.save` in the app.
  2. `updateCredentials` to the extension.
  3. If the tunnel is connected, the UI says "Takes effect on next connect"; we never force a reconnect.
- **"Forget password"** deletes both copies.
- **AUTH_FAILED with saved credentials** clears the extension's password copy, never the username. The prompt then shows `reason = .rejected`, and saving a new password re-provisions.
- **Deletion:** see `ProfileStore.delete`:
  1. disconnect if active;
  2. `removeFromPreferences`;
  3. extension `removeProfile`;
  4. DP keychain delete;
  5. delete the sealed file and metadata.
  6. If a step fails, the remaining steps still run and the failure is queued (§6.4).
- **Rename safety:** every key is the UUID. A rename changes `Profile.name` and `localizedDescription` only. It is allowed while connected, because saving a manager whose protocol configuration has not changed does not restart the tunnel. Spike S2 verifies this; the fallback is to defer the rename to disconnect.

### 6.7 Migrating legacy keychain items (L-MIG-1)

Format, from `internal/ovpn/keychain_darwin.go`:
- generic password items in the **login (file-based)** keychain;
- `service = "io.github.steiale.lockplus.ovpn"` (v1.0.57+), or `"io.github.steiale.wireguide-plus.ovpn"` (older);
- `account = <tunnel name>`;
- the value is one of:
  1. `"b64:" + base64(username + "\n" + basePassword)`, the current format;
  2. lowercase hex of the raw `username\npassword` bytes (pre-1.0.50 `security -w`);
  3. plain text, as a fallback.
- Split on the **first** `\n`: the username comes before it, the base password after.

Read path:
- `SecItemCopyMatching` with `kSecUseDataProtectionKeychain: false`, `kSecMatchSearchList: [login keychain]`, `kSecReturnData: true`.
- Accessing an item the Go binary created triggers **one** macOS "LockPlus wants to use your confidential information" prompt per item. The migration UI announces this up front, and the step is optional ("Import saved OpenVPN passwords").

Write path: `CredentialStore.save(newUUID, …)`, then provision. Legacy items are **never modified or deleted**.

### 6.8 Restore to a new Mac (Time Machine, Migration Assistant)

- The sealing key and saved credentials are `…ThisDeviceOnly` (§6.2), and the extension store is device-bound (§6.3). A restore or migration to **another** Mac brings `profiles/*.sealed` and metadata, but nothing that can open them. The profiles are unrecoverable from those files. A restore onto the **same** Mac (same Secure Enclave, keychain intact) is unaffected.
- Detection (one rule): `profiles/*.sealed` or `profiles/*.json` exist but the payload-key item is **missing** from the keychain. Nothing is inferred from HMAC results. With no key, no HMAC can be computed, so the metadata is **unverified**: it is used only to display names and is never written to NE preferences or provisioned. When the key item exists, a failing HMAC on a file is tampering (§3.4), not a lock. The app then shows "Profiles from another Mac are locked", with the profile names (from the unverified metadata) and three actions:
  - "Re-import" (file picker);
  - "Import from old LockPlus" (§13.1, if Go data exists);
  - "Remove locked profiles".
- It never generates a new key over existing sealed files or metadata, so a "new key" state with old files cannot arise. A new key is created only after the user removes the locked profiles or starts fresh, i.e. when no sealed file or metadata remains.
- **Nudge:** after the first successful import, and from Settings › General, the app suggests "Export all profiles" to a location of the user's choosing, with the warning "This file contains your VPN keys in plain text; store it somewhere safe" (Export-all is LAContext-gated, 0600, `O_NOFOLLOW`). The nudge is shown once, then lives in Settings.
- A passphrase-encrypted export format is listed in §21. v2.0 exports remain standard `.conf`/`.ovpn` files in a zip, so they stay portable to other clients.

---

## 7. Tunnel engine (inside the extension)

### 7.1 Structure

```
PacketTunnelProvider (NEPacketTunnelProvider subclass, ~150 lines, no logic)
   └── TunnelController (actor, TunnelEngine package; all logic, unit-testable)
         ├── ProviderHost (protocol; real impl wraps the provider)
         ├── TunnelAdapter (WireGuardAdapterImpl | OpenVPNAdapterImpl | FakeAdapter)
         ├── NetworkSettingsBuilder (pure: plan → NEPacketTunnelNetworkSettings)
         ├── PathWatcher (NWPathMonitor + provider.defaultPath)
         ├── Watchdog, Backoff, Clock (injectable)
         └── AuthBroker (prompt queue, promptID matching, timeouts)
```

```swift
public protocol ProviderHost: AnyObject, Sendable {
    func apply(_ settings: NEPacketTunnelNetworkSettings?) async throws   // setTunnelNetworkSettings
    func setReasserting(_ on: Bool)
    func cancel(with error: LPTunnelError)                                // cancelTunnelWithError
    var tunnelFileDescriptor: Int32? { get }                               // utun fd (§7.3)
}

public protocol TunnelAdapter: AnyObject, Sendable {
    var kind: VPNProtocolKind { get }
    /// Bring the session up. Returns only when the DATA PLANE is up (L-LC-2):
    /// WG: settings applied AND first handshake completed;
    /// OVPN: openvpn3 CONNECTED AND settings applied.
    func start(_ req: AdapterStart, events: AdapterEventSink) async throws(LPTunnelError)
    func stop() async
    func reconnect(reason: ReconnectReason) async         // path change, wake, watchdog
    func sleep() async
    func wake() async
    func provideAuth(_ answer: AuthAnswerSecrets) throws(LPTunnelError)
    func statistics() async -> AdapterStats
    func liveness() async -> Liveness                     // .healthy | .stale(age) | .dead
}

public struct AdapterStart: Sendable {
    let profileID: UUID; let payload: SecretBytes; let credentials: CredentialSecrets?
    let policy: NetworkPolicy; let connectTimeout: Duration
}

public enum AdapterEvent: Sendable {
    case networkSettings(NetworkPlan)        // adapter asks controller to apply (never applies itself)
    case reconnecting(ReconnectReason)
    case reconnected
    case authRequired(AuthPrompt)
    case fatal(LPTunnelError)
    case log(LogRecord)                      // pre-redacted
}

public struct AdapterStats: Sendable {
    var rxBytes: UInt64, txBytes: UInt64, lastHandshake: Date?
    var endpoint: String?, localAddresses: [String], cipher: String?
}
```

Every network setting flows through `NetworkSettingsBuilder` → `ProviderHost.apply`, so the DNS, MTU and route policy (§10) lives in one tested place.

### 7.2 State machine

States:
- `idle`
- `starting` (load and validate the provisioned payload, resolve endpoints)
- `connecting` (engine handshake)
- `awaitingAuth(prompt)`
- `establishing` (settings being applied)
- `connected`
- `reasserting(reason, attempt)`
- `sleeping`
- `stopping`
- `stopped(error?)`

| From | Event | To | Side effects |
|---|---|---|---|
| idle | `startTunnel(options)` | starting | Read `providerConfiguration`, load the payload from the container secret store (§6.3), **re-validate**, check the revision. Arm the **connect deadline** (WG 45 s, OVPN 90 s). |
| starting | validation or secret-store error | stopped | Fail the `startTunnel` completion with `.profileInvalid`/`.profileNotProvisioned`/`.secretStoreUnavailable`. |
| starting | ok | connecting | `adapter.start(…)`. |
| connecting | `authRequired` | awaitingAuth | **Pause the connect deadline** (L-RC-4) and start the auth deadline (10 min). Push `tunnelEvent(authRequired)` if an app is connected. |
| awaitingAuth | `answerAuth(promptID)` matching | connecting | Resume the connect deadline with its remaining budget. A non-matching `promptID` is rejected as `.staleAnswer` (drained; L-RC-4). |
| awaitingAuth | auth deadline / `cancelAuth` | stopped | `.authTimedOut` / `.authRequired`. |
| connecting | `networkSettings(plan)` | establishing | `host.apply(build(plan))`. |
| establishing | applied ok + adapter reports data plane up | connected | Call the `startTunnel` completion with `nil`. Start the session record, the watchdog and the path watcher. |
| establishing | apply throws | stopped | `.networkSettingsFailed`. |
| connecting/establishing | connect deadline | stopped | `.connectTimeout` (`startTunnel` completion error). |
| connected | path changed (interface or gateway set differs, still satisfied) | reasserting(.path) | `setReasserting(true)`, `adapter.reconnect(.pathChanged)` (L-RC-1). |
| connected | path unsatisfied | reasserting(.noNetwork) | `setReasserting(true)`. Wait for a satisfied path; no backoff consumed. |
| connected | watchdog `.stale` | reasserting(.deadPeer) | L-RC-2. |
| connected | adapter `.reconnecting` (openvpn3 RECONNECTING) | reasserting(.engine) | |
| reasserting | adapter data plane up (and settings reapplied if changed) | connected | `setReasserting(false)`, reset the backoff. |
| reasserting | attempt fails | reasserting(attempt+1) | Wait `backoff.next()` (§7.6). |
| reasserting | budget exhausted, **kill switch off** | stopped | `cancelTunnelWithError(.peerUnreachable)`. |
| reasserting | budget exhausted, **kill switch on** | reasserting | Keep retrying at the cap. Traffic is expected to stay blocked (fail closed; TBD-by-S2, §10.1). The UI shows "Reconnecting (blocked)". |
| any running | `sleep()` | sleeping | `adapter.sleep()`, stop the watchdog, then call the completion (L-RC-5). |
| sleeping | `wake()` | reasserting(.wake) | `setReasserting(true)`, `adapter.wake()`. UDP sockets are recreated. Must reach `connected` within 30 s or follow the normal backoff path. |
| any | adapter `.fatal(e)`, kill switch off | stopped | **`cancelTunnelWithError(e)` immediately** (L-LC-1). |
| any | adapter `.fatal(e)`, kill switch on | per §10.1 S2 outcome | Default (`blockMode = .cancel`): `cancelTunnelWithError(e)` immediately, as above. If S2 shows that `cancelTunnelWithError` **fails open** under `includeAllNetworks`: `blockMode = .holdBlocked`. The controller tears down the adapter (for OpenVPN this closes only openvpn3's `dup` of the utun fd, never NE's own descriptor, §7.3), keeps the provider alive with `reasserting = true` and **no** further retries, and records `lastError = e` with code `.blockedAfterFailure`. The status is `.reasserting`, never `.connected` (L-LC-1 still holds). It stays this way until the user disconnects or reconnects; turning the kill switch off requires disconnecting first (L-KS-2). This mirrors the Go `fwBlocked` state. |
| any | `stopTunnel(reason)` | stopping → stopped | `adapter.stop()` with a 5 s cap, write the session summary, then the completion. **The provider never calls `exit()` or `stopTunnel` itself** (NR §4 pitfall 10). |

Rules:
- `startTunnel`'s completion is called **exactly once**. A `CompletionOnce` wrapper asserts this in DEBUG and logs a fault in release.
- **"Connected" (L-LC-2):** the completion is called only after the data plane is up **and** `setTunnelNetworkSettings` has completed. `NEVPNStatus.connected` is therefore truthful.
- **The app has no other state source (L-LC-1, L-LC-4):** UI state comes from `NEVPNStatus`, plus `fetchLastDisconnectError` on `.disconnected`, plus `tunnelSnapshot` for detail only.

### 7.3 Data plane and fds

- **WireGuard:** WireGuardKit locates the utun fd that NE created by scanning fds for the `com.apple.net.utun_control` socket (upstream behaviour). Our fork keeps this.
- **OpenVPN:** **Decision:** openvpn3's `tun_builder_establish()` returns **`dup()` of the NE utun fd** (the fd itself is found by the same scan in `ProviderHost.tunnelFileDescriptor`), after the controller has applied the settings. openvpn3's `TunBuilderClient` (`openvpn/tun/builder/client.hpp`; the `tun/mac` client is not compiled, §8.1) then reads and writes utun frames on that descriptor.
  - **Why `dup` (N2):** `TunBuilderClient` stores the returned fd in a `TunPersist` = `TunPersistTemplate<ScopedFD>`. On macOS `retain_sd` is false (only iOS sets it, `cliopt.hpp`), so the wrapper is `TunWrapObjRetain::NO_RETAIN` and its `close()` **closes the fd** (`tun/persist/tunwrap.hpp`) whenever the tun client stops. Returning NE's own fd would let openvpn3 close the provider's utun descriptor on the first reconnect, AUTH_FAILED or stop. wireguard-apple dups for the same reason (`unix.Dup(tunFd)`, `api-apple.go:91`, used at line 103). The shim owns nothing beyond the dup: openvpn3 closes it, NE keeps its original.
  - **Reconnects:** with `tunPersist = false` (the default), the `TunPersist` is short-term, so every engine-internal reconnect closes the descriptor and calls `tun_builder_new()` … `tun_builder_establish()` again. Each call returns a fresh `dup()`, and the controller re-applies settings only when the plan changed. With `tunPersist = true`, openvpn3 keeps the descriptor across reconnects when the pushed tun properties are unchanged (`use_persisted_tun`, then `tun_builder_establish_lite()`) and enables remote DNS caching. S11 evaluates `tunPersist = true` (fewer settings re-applies and less churn during `reasserting`) against its cost (a persisted tun across a server change must still re-apply `tunnelRemoteAddress`, §8.5). Until S11 decides, `tunPersist = false`.
  - **AF header:** `cliopt.hpp` sets `tun_prefix = true` for `OPENVPN_PLATFORM_MAC` in the tun-builder path, so the builder client already reads and writes the 4-byte utun AF header. S11 confirms it on the wire.
  - **`holdBlocked` (§7.2):** tearing down the adapter closes only openvpn3's dup. NE's utun fd and the provider's `reasserting` state stay intact, so the blocked session persists.
  - **Assumption A-OVPN-FD:** this works with openvpn3's `TunBuilderClient` on macOS. Spike S11 validates it.
  - **Fallback:** a `socketpair(AF_UNIX, SOCK_DGRAM)` bridge, where a Swift pump moves packets between `packetFlow.readPackets` and the pair, adding or stripping the AF header. It costs about 10–15 % of throughput, which is acceptable.

### 7.4 Path monitoring and sleep/wake (L-RC-1, L-RC-5)

- `PathWatcher` combines `NWPathMonitor()` (no interface restriction) with KVO on `provider.defaultPath`.
  - It debounces for 500 ms and emits `.changed(PathSnapshot)` only when `(status, interface names+types, gateways, isExpensive)` actually changed.
  - It ignores the tunnel's own utun.
- WireGuard: on change, the fork's `WireGuardAdapter` already calls `wgBumpSockets` and re-resolves endpoints. The controller then forces a handshake (§9.3) and waits up to 15 s.
- OpenVPN: `client.reconnect(0)`, which gives a new transport socket on the new interface.
- Sleep:
  - `disconnectOnSleep = false`.
  - `sleep(completionHandler:)`: WG stops the watchdog only (wireguard-go timers survive); OVPN calls `client.pause("sleep")`.
  - The completion is called within 2 s.
- Wake:
  - `reasserting = true`.
  - WG: `wgBumpSockets` + forced handshake.
  - OVPN: `client.resume()`, then `client.reconnect(0)` if not CONNECTED within 5 s.
  - Both recreate UDP sockets.
  - Failure after the backoff budget → `cancelTunnelWithError` (kill switch off) or keep blocking (kill switch on).

### 7.5 Handshake watchdog (L-RC-2)

The watchdog ticks every 10 s while `connected`.
- **WireGuard:**
  - `age = now − lastHandshake` from `getRuntimeConfiguration` (`last_handshake_time_sec`).
  - When `age > 180 s` (REJECT_AFTER_TIME) **and** tx bytes grew since the last tick, the adapter is `.stale`. It forces a handshake and gives it 3 × 5 s.
  - Still stale → reasserting(.deadPeer) with endpoint re-resolution.
- **OpenVPN:**
  - openvpn3 keepalive/`ping-restart` handles dead peers internally and reports `RECONNECTING`.
  - Our floor: if the profile has no `ping`/`ping-restart`/`keepalive`, normalization appends `ping 10` + `ping-restart 60` (ported from the Go `args()` floors). openvpn3 lists `ping`/`ping-restart` as push-only (`settings_pushonlyoptions`, fatal if left untouched), but `ProtoContext::Config::load` reads them from the profile, which touches them. The §8.1 `ClientOptions` check proves that the floored canonical profile is accepted; if a future openvpn3 stops reading them, the floor is dropped and the watchdog check below becomes the only floor.
  - The watchdog additionally checks that `transport_stats().lastPacketReceived` is younger than 120 s.

### 7.6 Backoff and timeouts (L-RC-3)

```swift
struct Backoff { // full jitter, capped
    var base: Duration = .seconds(1), cap: Duration = .seconds(60), factor = 2.0, attempt = 0
    mutating func next() -> Duration   // random(0.8…1.2) * min(cap, base * factor^attempt)
    mutating func reset()
}
```

- Every retry loop in the codebase uses `Backoff`; a lint rule flags `while` + `sleep` without it.
- The kill-switch-off budget is 5 min of reasserting; with the kill switch on it is unbounded at the cap.
- AUTH_FAILED is **never** retried automatically with the same stored credentials. It always produces a prompt (account-lockout protection).
- openvpn3 `connTimeout = 0`; we enforce our own deadline, which pauses during auth.
- When openvpn3 reports a server-requested restart pause (`RECONNECTING` with a delay), we honour `max(serverDelay, backoff)`. This is the c15d1ba lesson.

### 7.7 Statistics and sessions

- `statistics()` costs:
  - WG: one `getRuntimeConfiguration` call, parsing `rx_bytes`, `tx_bytes` and `last_handshake_time_sec` per peer (summed);
  - OVPN: `transport_stats()` (`bytesIn`/`bytesOut`), `connection_info()` (vpnIp4/6, serverHost, serverPort, serverProto).
- The app polls at 1 Hz while the menu-bar rate display is on or the stats view is visible, and at 0.2 Hz otherwise. The extension caches stats for 250 ms.
- Sessions: the controller mints a session UUID at `connected`. At `stopped` it appends `SessionSummary(id, profileID, start, end, rx, tx, endReason)` to a 100-entry ring in `state.plist`.
- The app pulls `sessionSummaries(after:)` on launch and on every `.disconnected`, and merges into `history.json` keyed by session UUID. History is correct even for on-demand sessions that run while the app is closed.

---

## 8. OpenVPN specifics

### 8.1 Import pipeline (L-OVPN-1)

```
untrusted bytes
  → [1] size cap (1 MiB), NUL check, UTF-8 not required (bytes)
  → [2] OVPNTokenizer  (Swift line-for-line port of internal/ovpn/parse.go: parseLine, fgets/buf_parse,
                       readInline prefix-close semantics, <connection> re-parse, BOM, OPTION_LINE_SIZE=256,
                       OPTION_PARM_SIZE=256, MAX_PARMS=16, bypass_doubledash)
  → [3] Allowlist      (port of internal/ovpn/allowlist.go + inspectProfile: rules, inline modes,
                       setenv/setenv opt recursion, ports, providers, dev/dev-type, http/socks proxy)
  → [4] EngineSupport  classify each accepted directive: .mapped | .ignored(reason) | .unsupported(reason)
                       (table GENERATED from openvpn3's lists, see §8.2)
  → [5] Normalizer     emit CANONICAL text: one directive per line, every argument double-quoted with
                       only \\ and \" escapes, inline blocks as "<name>\n…\n</name>" with body lines
                       validated (no line starting with "</"), comments dropped, ignored directives dropped,
                       floors appended (ping/ping-restart, mssfix 1300 only if no MTU directive),
                       inline <auth-user-pass> EXTRACTED to CredentialRecord and removed.
                       Caps on the OUTPUT: total ≤ 256 KiB (openvpn3 MAX_PROFILE_SIZE = 262144),
                       every line incl. inline-block body lines ≤ 512 bytes (MAX_LINE_SIZE),
                       directive names ≤ 64 chars (MAX_DIRECTIVE_SIZE); over ⇒ reject with the limit named
  → [6] Differential   OpenVPN3Options.parse(canonical) → [[String]] must equal our directive stream
                       exactly (names, args, inline bodies); mismatch ⇒ reject "parser disagreement"
  → [7] openvpn3 check (extension, validateProfile XPC):
                       (a) ClientAPI eval_config(canonical) → EvalConfig: error/message,
                           staticChallenge(+echo), autologin, privateKeyPasswordRequired,
                           remoteHost/Port/Proto, serverList;
                       (b) construct ClientOptions(options, cc) with a no-op TunBuilder stub and no
                           transport start; its constructor runs handle_unused_options and throws
                           UNUSED_OPTIONS for unknown, removed, server-only, push-only, standalone,
                           not-implemented-fatal and management* directives. Any throw ⇒ reject,
                           with openvpn3's category text mapped to our "Not supported" group (§8.3)
  → ImportReport + Profile + canonical payload
```

- Steps [1]–[6] run in the app at import. Step [7] runs at import too, through the `validateProfile` XPC, so `UNUSED_OPTIONS` surfaces **before** the profile is saved, not at `connect()`. If the extension is unavailable at import, the profile is saved as "Not yet verified", and Connect is disabled until [7] passes.
- *Why [7b] is needed:* `eval_config` (`OpenVPNClientHelper::parse_config`) does **not** call `handle_unused_options`. Only the `ClientOptions` constructor does, at `cliopt.hpp` ≈ line 596, and that constructor normally runs inside `connect()` (`ovpncli.cpp`, `new ClientOptions(state->options, cc)`). Constructing `ClientOptions` performs no network I/O. S13 confirms the stub construction is side-effect free (TBD-by-S13). If it is not, the shim calls a vendored copy of `handle_unused_options` over the parsed `OptionList` after running the same `touch()`ing parse steps, and a unit test pins that copy to upstream.
- The extension repeats [1]–[7] in `provisionProfile` **and** [1]–[6] again before every `startTunnel`.
- The engine only ever sees canonical text that two independent parsers agree on, and that the engine's own option consumer accepted, so a tokenizer divergence cannot become a bypass.
- **Build rules for openvpn3 (MUST):**
  - compile with `-DUSE_TUN_BUILDER`. Without it, `cliopt.hpp` selects `openvpn/tun/mac/client/tuncli.hpp` on macOS, whose `tunsetup.hpp` shells out to `/sbin/route` and `ifconfig`;
  - exclude `openvpn/tun/mac/client/*` from the build; CI greps the extension's symbols for `MacTun`/`TunMac` and fails if found;
  - no `OPENVPN_COMMAND_AGENT`, no `OPENVPN_EXTERNAL_TUN_FACTORY`, no script support, no file access. The sandbox would deny exec and file access anyway; the build rules make it impossible rather than merely denied.

### 8.2 Directive mapping

The Go allowlist was written for openvpn **2.7**; openvpn3 supports a subset. Draft 1 asserted openvpn3's handling per directive. Draft 2 **derives** it, because openvpn3 rejects at `connect()` (via `handle_unused_options`, `cliopt.hpp` ≈ 945) every directive that its option consumers did not `touch()`, unless the directive is on a non-fatal list.

**How `EngineSupport` is generated (`Tools/gen-engine-support`, run on every openvpn3 submodule bump):**
1. Extract openvpn3's lists from the pinned `openvpn/client/cliopt.hpp`. Each list maps to a class:
   - `settings_ignoreWithWarning`, `settings_feature_not_implemented_warn` and `settings_script_plugin_feature` are non-fatal ("Unsupported option (ignored)" etc.) → **ignored(warn)**, dropped from canonical text;
   - `settings_ignoreSilently` → **ignored(silent)**, dropped;
   - `settings_removedOptions`, `settings_serverOnlyOptions`, `settings_standalone_options`, `settings_feature_not_implemented_fatal`, `settings_pushonlyoptions` and any `management*` directive are fatal if untouched → **unsupported** unless step 2 proves the profile parser touches them;
   - a directive on no list is fatal if untouched (`UNKNOWN/UNSUPPORTED OPTIONS`) → **unsupported** unless step 2 proves otherwise.
2. **Empirical touch test:** for every directive on the Go allowlist, the generator builds a minimal valid client profile plus that directive (with representative arguments from the shared fixtures) and runs [7b] (`ClientOptions` construction) in a host-side test binary.
   - Accepted with no warning → **mapped**.
   - Accepted with a warning → **ignored(warn)**.
   - `UNUSED_OPTIONS` → **unsupported**, or, if the directive is harmless and droppable, **ignored(warn)** by a reviewed override list in `EngineSupportOverrides.swift`, which records the reason.
3. Emit `LPParsing/OVPNEngineSupport.generated.swift`. It is committed, and the openvpn3 tag is recorded in its header.

Tests:
- A unit test regenerates the table in CI and **diffs** it against the committed file. Any difference fails the build, so a submodule bump cannot silently change the classification.
- A second test asserts that the table covers exactly the allowlist's key set.

Expected classification (draft 1's table, corrected by reading openvpn3 `master`; the generated table is authoritative where they differ):

| Group | Directives | Expected class (from the lists; TBD-by-generator where a directive is fatal-if-untouched) |
|---|---|---|
| Role/transport | `client`, `tls-client`, `pull`, `proto`, `remote`, `remote-random`, `port`, `rport`, `server-poll-timeout`, `<connection>` | mapped |
| | `nobind` | ignored(silent) |
| | `resolv-retry`, `connect-retry(-max)`, `explicit-exit-notify` | ignored(warn) (openvpn3 lists them as "Unsupported option (ignored)") |
| | `bind`, `float` | `bind`: ignored(warn) (not-implemented-warn); `float`: TBD-by-generator |
| Proxy | `http-proxy host port`, `<http-proxy-user-pass>`, `http-proxy-option` | mapped (credentials → `proxyUsername/Password` in Config) |
| | `socks-proxy` | **unsupported** (`settings_feature_not_implemented_fatal`) |
| TLS/crypto | `ca`/`cert`/`key`/`extra-certs`/`tls-auth`/`tls-crypt`/`tls-crypt-v2`/`pkcs12` (inline), `remote-cert-tls`, `verify-x509-name`, `peer-fingerprint`, `auth`, `cipher`, `tls-version-min`, `tls-cipher`, `tls-ciphersuites`, `tls-cert-profile`, `key-direction`, `reneg-sec` | mapped (tls-crypt-v2 per spike gate) |
| | `data-ciphers(-fallback)`, `ncp-ciphers`, `tls-version-max` | ignored(warn) (openvpn3 negotiates via IV_CIPHERS; §8.6 uses them only to set our legacy flag) |
| | `dh` | dropped from canonical text with a warning (server-only: fatal if passed through) |
| | `verify-hash` | dropped with a warning (fatal if passed through) |
| | `crl-verify` | TBD-by-generator; if unsupported, dropped with a warning "CRL not checked" |
| Compression | `comp-lzo`, `compress` | mapped. **Decision:** `compressionMode = "asym"` (decompress only, VORACLE) |
| | `allow-compression` | ignored(warn) |
| DNS/routes | `dhcp-option`, `dns`, `route`, `route-ipv6`, `route-nopull`, `redirect-gateway`, `redirect-private`, `block-ipv6`, `pull-filter`, `route-metric` | mapped (`PushedOptionsFilter` for pull-filter/route-nopull); TBD-by-generator for each |
| | `topology`, `route-gateway` | **push-only** in openvpn3 (fatal if untouched in a profile). Expected: dropped from the profile with an info note ("set by the server"); TBD-by-generator |
| MTU | `tun-mtu`, `mssfix` | mapped |
| | `link-mtu` | ignored(warn) |
| | `mtu-disc` | ignored(warn) (not-implemented-warn) |
| | `fragment` | **unsupported** (reject: the server requires it) |
| Liveness | `ping`, `ping-restart` | mapped (touched by `ProtoContext::Config::load` despite being on the push-only list; confirmed by the touch test) |
| | `keepalive` | expected mapped (also read by `ProtoContext`, although it is on `ignoreWithWarning`); TBD-by-generator |
| | `ping-exit`, `inactive` | TBD-by-generator; `ping-exit` is push-only |
| | `ping-timer-rem` | **unsupported** in openvpn3 (fatal list) → dropped with a warning (it only matters for p2p) |
| Auth | `auth-user-pass` (bare or inline), `auth-nocache`, `static-challenge`, `push-peer-info` | mapped |
| | `auth-retry` | ignored(warn) (superseded by our prompt flow) |
| Logging | `verb`, `mute-replay-warnings` | ignored(silent) |
| | `mute` | ignored(warn) |
| Harmless/Windows/Linux | `persist-*`, `fast-io`, `sndbuf`, `rcvbuf`, `socket-flags`, `tun-ipv6`, `disable-occ`, `disable-dco`, `ignore-unknown-option`, `script-security`, `dns-updown disable`, `user`, `group`, `route-method`, `block-outside-dns`, `register-dns`, `ip-win32`, `dhcp-renew`, `dhcp-release`, `dhcp-pre-release`, `tap-sleep`, `providers`, `setenv`/`setenv-safe` (UV_/IV_ and listed names) | ignored (dropped from the canonical text) |
| `setenv opt X …` | inner X is checked by the allowlist, then classified as X | as X |
| `dev`/`dev-type` | `tun` only (allowlist) | mapped as `dev tun` |
| `management*`, `log*`, `status`, `daemon`, `writepid`, … | not on the Go allowlist | **forbidden** (and fatal in openvpn3) |
| Everything not on the allowlist | | **forbidden** (import rejected; line and name shown, never the arguments) |

Directives classed "dropped" never reach openvpn3, so they cannot trigger `UNUSED_OPTIONS`. The [7b] check is the backstop for anything the table gets wrong.

### 8.3 Unsupported-directive UX

- The import sheet shows the profile name, endpoint and protocol, then three collapsible groups:
  - **Will be ignored** (grey), e.g. "line 12 `verb` — logging is managed by LockPlus";
  - **Not supported** (red);
  - **Security warnings** (orange): "server identity not pinned", "legacy cipher BF-CBC", "compression enabled by server".
- Any *Not supported* or *forbidden* item disables Import. The user can copy the report.
- The report is persisted in `Profile.importReport` and shown again in Detail › Profile info.
- Multi-file and zip imports show one row per file with ✔/⚠/✖ and the same per-file reports. This is the `ZipImportResult` UX.

### 8.4 Auth flows (L-OVPN-3, L-RC-4)

`EvalConfig` determines the up-front needs:
- `autologin == false` → user/password needed;
- `staticChallenge != ""` → an SC prompt with `staticChallengeEcho`;
- `privateKeyPasswordRequired` → passphrase.

The shim sets:
- `Config.ssoMethods = ""`, so IV_SSO is never advertised;
- `retryOnAuthFailed = false`, `autologinSessions = true`, `info = true`.

`ProvideCreds` (`client/ovpncli.hpp`, current `master`) has exactly `username`, `password`, `http_proxy_user`, `http_proxy_pass`, `response` and `dynamicChallengeCookie`. It has **no** `cachePassword` or `replacePasswordWithSessionID` fields (those existed in older openvpn3 releases). Credential caching is internal: `ClientCreds` keeps the username/password for the session and prefers a server-pushed `auth-token` (`session_id`) on reconnect when one exists (`openvpn/client/clicreds.hpp`). The shim must not assume any per-call caching control. The only levers are what we pass to `provide_creds`, and `ClientCreds::purge_user_pass()` through a minimal, vendored patch (`Vendor/patches/openvpn3/0001-expose-purge-user-pass.patch`) that exposes **only** that one call on `OpenVPNClient` (N8). `purge_session_id()` is not exposed: openvpn3 already purges the session ID itself when the server rejects the auth-token, and every extra exposed call is patch surface to rebase.

Facts the auth design relies on (openvpn3 `master`, verified for draft 3):
- `purge_user_pass()` clears the **username and** the password (`clicreds.hpp`), not just the password.
- `client_auth` (`cliproto.hpp`) throws `NEED_CREDS` when no session ID exists, a password is needed and none is defined. It throws **before** `write_auth_string`, so after a purge nothing (in particular no spent OTP) is sent to the server (M6).
- `NEED_CREDS` is **fatal**: `cliconnect.hpp` emits the `NEED_CREDS` event and calls `stop()`. There is no "provide creds and continue" path inside the same `connect()`.
- Consequence for `awaitingAuth(.reconnect)`: on `NEED_CREDS` the shim reports `authRequired(.reconnect)`, the `connect()` call returns, and the answer is delivered with `provide_creds` carrying the **username again** (from `CredentialRecord`, or the CRV1 `lockedUsername`) plus the fresh password/OTP, followed by a **fresh `connect()`**. The controller stays in `reasserting` (status never `.connected`) across that gap, and the utun descriptor is re-established through the normal `tun_builder_establish()` path (§7.3).
- openvpn3 also honours the `auth-nocache` directive natively (`ssl/proto.hpp` reads it for client and pushed options; `cliproto.hpp` calls `purge_user_pass()` after every auth write and after a pushed `auth-nocache`). S8 evaluates injecting `auth-nocache` into the canonical text of OTP profiles as a patch-free alternative; if it behaves identically, the patch is dropped.

| Flow | Sequence |
|---|---|
| Password (saved) | Extension loads the creds, then `provide_creds(username, password)` before `connect()`. No prompt. |
| Password (not saved / `appendOTP`) | Controller → `awaitingAuth(.userPass)` → app shows the prompt (username prefilled, password empty). With `appendOTP`, the sheet shows a saved-password field plus a "One-time code" field, and the app concatenates `base + otp` into `password`. The answer goes to `provide_creds`, then `connect()`. "Save" persists the **base** password only. |
| Static challenge (SC) | Prompt has the password field plus the challenge text as a label and a response field (echo per flag). `ProvideCreds.response = response`; openvpn3 builds `SCRV1:b64(pw):b64(resp)`. If the profile requests the **concat** format and openvpn3 lacks it (spike S8), the shim sets `password = pw + resp` and `response = ""` (Go `combineStaticChallenge` semantics). |
| Dynamic challenge (CRV1) | `connect()` returns after event `DYNAMIC_CHALLENGE` with the cookie in `info`. `OpenVPNClientHelper::parse_dynamic_challenge(cookie, dc)` → prompt `.dynamicChallenge(text: dc.challenge, echo: dc.echo)`, plus a **read-only username decoded from the cookie's base64 field** (`lockedUsername`). The answer goes to `ProvideCreds{username: <from cookie>, response, dynamicChallengeCookie: cookie}`, then a new `connect()`. The connect deadline is paused throughout. |
| AUTH_FAILED | Event `AUTH_FAILED` (`fatal` or not). If creds were stored: clear the extension's password copy, then prompt `reason: .rejected` with the server's reason text (sanitized, ≤ 200 chars) shown as secondary text. If they were not stored: prompt `.rejected`. **Never** auto-retry. After 3 consecutive rejections within 10 min: `cancelTunnelWithError(.authFailed)`. |
| Reconnect requiring auth | openvpn3's **internal** reconnect (ping-restart, transport error, our `reconnect(0)`) re-sends the cached credentials, or the `auth-token` if the server pushed one. For OTP profiles (`appendOTP`, static challenge, CRV1) a re-sent password contains a **spent OTP**. Servers count that as a failed login, and repeated reconnects can lock the account (M6). Rule: after CONNECTED, the shim calls `session_token()`. **With an auth-token:** keep engine-internal reconnects. **Without one, on an OTP profile:** the shim immediately calls `purge_user_pass()`, so no stale OTP can be re-sent. The next internal reconnect (or TLS renegotiation) then hits `NEED_CREDS`, which is thrown before any auth string is written and ends the `connect()` call. The controller enters `awaitingAuth(reason: .reconnect)` with the backoff/budget paused, the user enters a fresh code, and the answer re-supplies username + password and starts a fresh `connect()` (see the facts above). Renegotiation (`reneg-sec`) without an auth-token therefore also prompts; S8 records the servers' `reneg-sec`. If the server rejects the auth-token itself (`AUTH_FAILED` on reconnect), the token is purged and the same prompt is used. Non-OTP profiles keep cached credentials for reconnects. S8 verifies that BHP and AllService push `auth-token` (TBD-by-S8) and that purging prevents any re-send, checked in the test server's auth log. By the source, a purged-credential reconnect cannot reach the server (`NEED_CREDS` precedes the write); S8 confirms it in the auth log. If S8 nevertheless shows a failed login, the fallback is to **disable engine-internal reconnect for OTP profiles without a token**: on the `RECONNECTING` event the shim calls `stop()`, the controller prompts, and the answer starts a fresh `connect()`. |
| Web/SSO | Event `INFO` with `WEB_AUTH:`/`OPEN_URL:`/`CR_TEXT:` → `cancelTunnelWithError(.webAuthUnsupported)` immediately (no hang). The import pre-check warns when the profile contains `setenv IV_SSO` (stripped). |
| Encrypted key | Supported: `Config.privateKeyPassword` from `CredentialRecord.keyPassphrase` or a `.keyPassphrase` prompt. |
| Proxy auth without inline creds | `.unsupported` at import (the Go `msgProxyAuth` equivalent). |

Prompt delivery:
- If an app connection exists, `tunnelEvent(authRequired)` is pushed.
- On every app launch and every `NEVPNStatus` change to `.connecting`, the app calls `pendingAuthPrompt`.
- The menu bar shows "Authentication required…" and the main window raises a sheet.
- If no app answers within the 10 min auth deadline: `.authTimedOut`.
- **Assumption:** on-demand profiles that need interactive auth are rejected as on-demand targets in the UI ("Requires a one-time code; can't auto-connect").

Stale answers:
- Every prompt has a fresh `promptID`. `answerAuth` with a non-current ID returns `.staleAnswer`, and the app discards its form. This replaces the Go `authCh` drain.

### 8.5 Pushed options and DNS mapping (L-DNS-2)

openvpn3 merges profile and pushed options, applies `pull-filter` (accept/ignore/reject, first match wins, matching the Go `filterPushed`) and `route-nopull`, and then calls the TunBuilder callbacks. Our shim's `TunBuilder` collects a `NetworkPlan`:

```swift
public struct NetworkPlan: Sendable, Equatable {
    var ipv4: [IPv4Assignment], ipv6: [IPv6Assignment]
    var includedRoutes4: [Route4], excludedRoutes4: [Route4], includedRoutes6, excludedRoutes6
    var redirectGateway: (v4: Bool, v6: Bool), blockIPv6: Bool
    var dns: DNSPlan, mtu: Int?, remoteAddress: String   // remoteAddress from tun_builder_set_remote_address
}
public struct DNSPlan: Sendable, Equatable {
    var servers: [String]            // ordered by priority
    var searchDomains: [String]
    var splitDomains: [String]       // resolve-domains / DOMAIN when split
    // DoH/DoT transports are cut from v2.0 (§21); `transport DoH|DoT` servers are used as plain DNS inside the tunnel
}
```

| Source | Maps to |
|---|---|
| `dns server N address A …` (2.7 profile or push; a pushed priority replaces the profile's) | `servers`, ordered by ascending N; a `:port` suffix is stripped (Go `stripDNSPort`) |
| `dns server N resolve-domains d …` | `splitDomains` |
| `dns search-domains d …` | `searchDomains` |
| `dns server N transport DoH\|DoT`, `sni` | ignored with an import/connect note ("encrypted DNS transport not used; queries go in plain text inside the tunnel"). The server addresses are still used (§10.3) |
| `dhcp-option DNS`/`DNS6` | `servers`, **only if no `dns server` exists** (2.7 semantics, Go `dnsConfig.entries`) |
| `dhcp-option DOMAIN` | `searchDomains`; also `splitDomains` when `dnsMode == .split` |
| `dhcp-option DOMAIN-SEARCH` | `searchDomains` |
| PUSH_UPDATE changing DNS/routes | openvpn3 re-runs the tun builder (if supported; S13) → the controller re-applies settings with a short `reasserting` |

- The callbacks used: `tun_builder_set_dns_options(const DnsOptions&)` (openvpn3 ≥ 3.10). The legacy `tun_builder_add_dns_server`/`add_search_domain` are kept as fallbacks if a pinned version still emits them.
- **Endpoint protection (replaces draft 1's "drop routes covering the endpoint").** That rule would have discarded the pushed `0.0.0.0/1` + `128.0.0.0/1` pair (`redirect-gateway def1`), because both halves "cover" some endpoint, silently turning a full tunnel into a split one. Instead:
  - `NEPacketTunnelNetworkSettings(tunnelRemoteAddress:)` is set to the address openvpn3 reports via `tun_builder_set_remote_address` (the connected server IP);
  - `NetworkSettingsBuilder` adds that address as an **excluded route** (`/32` or `/128`) in the matching family, so a pushed route can never capture the transport;
  - every included route is kept as pushed, subject to the cap and `pull-filter`.
  - On macOS in TunBuilder mode, openvpn3 does **not** add remote-bypass routes itself. `TunProp::Config::remote_bypass` is set only (a) in the non-agent native-tun paths (`tun/mac` and `tun/win` clients, when `tunPersist` is on), and (b) under `USE_TUN_BUILDER` only for `OPENVPN_PLATFORM_IPHONE` with `tunPersist` (`cliopt.hpp`). `add_bypass_route` itself appears in the command-agent and native-tun setup code, none of which we compile (§8.1). So on macOS this is our job, even with `tunPersist = true` (§7.3).
  - NE already exempts the provider's own sockets from the tunnel, so the excluded route is defence in depth. Whether it is honoured under `includeAllNetworks` is TBD-by-S2. Either answer is safe, because the provider-socket exemption is what carries the traffic.
  - On a reconnect to a different server IP (remote list failover), the settings are re-applied with the new `tunnelRemoteAddress` and excluded route.
- Pushed-route caps: at most 1024 routes; routes with prefix length < 1 are only honoured via `redirect-gateway`.

### 8.6 Legacy CBC and crypto (L-OVPN-2)

- `cipher X` without `data-ciphers`, where X is a CBC cipher, is the 2.7 trap that the Go `legacyDataCiphers` shim fixed.
- openvpn3 negotiates via IV_CIPHERS and still honours `cipher` as the fallback for non-NCP servers. The non-AEAD data channel requires `Config.enableNonPreferredDCAlgorithms = true`.
- **Decision:** the normalizer sets a per-profile `legacyCrypto` flag when:
  - `cipher` names a non-AEAD cipher **and** no `data-ciphers` lists only AEAD ciphers; **or**
  - `auth` names SHA1/MD5 with a CBC cipher.
- That flag sets `enableNonPreferredDCAlgorithms = true`.
- `BF-CBC`, DES and RC2 additionally set `enableLegacyAlgorithms = true`. This needs OpenSSL's legacy provider, which our static build includes with `no-module` (the Go `providers legacy default` equivalent).
- `cipher none` is rejected at import.
- The UI shows a "Legacy encryption" badge on the profile.
- Spike gate: a CBC-only server connects.

### 8.7 Logging (L-OVPN-2)

- openvpn3 has no `verb`. The shim's `log(const LogInfo&)` forwards each line through `OVPNLogRedactor` before it reaches `Logger`:
  - lines containing `auth-token`, `PUSH_REPLY`/`PUSH_UPDATE` keep only the option **names**;
  - `CRV1`/`SCRV1`/`password`/`private key` lines are dropped;
  - IPv4/IPv6 addresses and hostnames are logged `.private`.
- `sslDebugLevel = 0`.
- `OPENVPN_DEBUG_VERBOSE_ERRORS` and any packet-dump defines are banned in the build script, and CI greps the compile flags.
- Log levels: default `.info` (state transitions, cipher, error codes); `.debug` adds the redacted engine lines. There is no level at which keys or packets are logged.

---

## 9. WireGuard specifics

### 9.1 Parser and validator (port of `internal/config`)

`LPParsing/WGConfig.swift`:
- **wg-quick compatible:**
  - strip a UTF-8 BOM;
  - **strip everything from the first `#`** (`${line%%\#*}`);
  - skip `;` comment lines;
  - section names are case-insensitive;
  - `key = value` splits on the first `=`;
  - keys are case-insensitive;
  - repeated `Address`, `DNS` and `AllowedIPs` lines accumulate.
- **Bare IPs** in `Address`/`AllowedIPs` get `/32` or `/128` (`splitPrefixes`).
- `DNS` entries: an IP is a server; a hostname matching the RFC 1035 regex is a search domain.
- Unknown keys are preserved in `extraKeys` for export round-trips.
- `PreUp`/`PostUp`/`PreDown`/`PostDown`, `Table` and `FwMark` are preserved but **never executed or applied**. The import report lists them as "ignored".
- Errors never echo line contents (a key could leak).

Validator rules (port of `validator.go`):
- keys are base64 of 32 bytes;
- addresses and AllowedIPs are CIDRs;
- the endpoint is `host:port`, with the host an IP or RFC 1035 name and the port 1–65535;
- MTU 576–65535 if set (**Decision:** a warning above 9000);
- ListenPort 1–65535;
- PersistentKeepalive 0–65535;
- at least one peer;
- **no CR/LF in any value**, extra keys included;
- the `Table` and `FwMark` syntax is checked.

The validator returns `[ValidationIssue(field: "Peer[0].Endpoint", message: LocalizedStringResource)]`, so the editor can attach issues to lines.

### 9.2 WireGuardKit fork strategy

- The fork lives at `github.com/steiale/wireguard-apple`, branch `lockplus`, pinned by submodule SHA. Our patches are kept as a reviewed series in `Vendor/patches/wireguard-apple/*.patch` and rebased quarterly.
- Patches:
  1. **Current wireguard-go:** `Sources/WireGuardKitGo/go.mod` bumped to the latest tagged wireguard-go and Go toolchain 1.25+; dead iOS-only code removed. The Makefile builds arm64 only.
  2. **Settings applier injection:** `WireGuardAdapter.init(with:settingsApplier:logHandler:)`. Instead of calling `packetTunnelProvider.setTunnelNetworkSettings`, the adapter hands its generated plan to our closure, so DNS, MTU and routes follow §10.
  3. **Forced handshake:** a new export `wgSendHandshake(handle)` calls `peer.SendHandshakeInitiation(false)` for every peer. It is used for data-plane-up detection and by the watchdog.
  4. **Endpoint list:** `resolveAllEndpoints` returns every resolved address (v4 and v6). The adapter tries them in order on handshake failure (L-MTU-1, "try every resolved endpoint IP").
  5. **Log hygiene:** the wireguard-go log callback is mapped to levels; no key material is logged (upstream already logs only public-key prefixes).
- Build: an Xcode **External Build System** target `WireGuardGoBridge` runs `make -C Vendor/wireguard-apple/Sources/WireGuardKitGo` with `GOARCH=arm64`, `CGO_ENABLED=1`, `-trimpath`, `-buildvcs=false`, writing `libwg-go.a` into `$(BUILT_PRODUCTS_DIR)`.
  - The Go toolchain version is pinned in `Vendor/go-toolchain.txt`. CI installs exactly that version.
- Monthly CI job "dependency watch": diffs upstream wireguard-go, wireguard-apple, openvpn3 and OpenSSL tags and opens an issue.

### 9.3 Endpoint resolution, data-plane-up, MTU (L-MTU-1)

- Resolution happens in the extension via `getaddrinfo` with `AI_ADDRCONFIG` (WireGuardKit's `DNSResolver`), **before** settings are applied, because a kill-switch tunnel would otherwise route the lookup into itself.
  - All A and AAAA records are kept. NAT64 synthesis follows the upstream code.
  - Failure → `.dnsResolutionFailed` (retried under the backoff).
- **Data plane up:** after `adapter.start` completes (settings applied), the controller calls `wgSendHandshake` and polls `last_handshake_time_sec` every 250 ms.
  - The first nonzero value newer than start means connected.
  - It retries the handshake every 5 s and moves to the next endpoint IP after 2 failures, up to the 45 s connect deadline.
- MTU:
  - `NEPacketTunnelNetworkSettings.mtu` is **always** set explicitly: `policy.mtuOverride ?? config.MTU ?? 1420`.
  - **Decision:** default 1420 for an IPv4 endpoint and 1400 for an IPv6 endpoint.
  - The value is shown in Detail. A parse failure is an import error, never a silent fallback (the c7e3a74 lesson).
- MSS: NE does not clamp MSS. For WireGuard the MTU is the lever. For OpenVPN, `mssfix 1300` is the floor (§8.1). The fragment and RDP/SMB cases stay in the harness (L-KS-4).
- Keepalive floor: WG profiles without `PersistentKeepalive` stay as they are (the user's choice), but the import report suggests 25 s when the kill switch is on.
- IPv6 for v4-only full tunnels: §10.5.

---

## 10. Network policy

### 10.1 Kill switch (L-KS-2, L-LC-4)

`NetworkPolicy` → `NETunnelProviderProtocol`:

| Profile | `killSwitch` | Settings |
|---|---|---|
| full tunnel (WG `0.0.0.0/0`/`::/0`, OVPN `redirect-gateway`) | on | `includeAllNetworks = true`, `excludeLocalNetworks = allowLAN`, `excludeAPNs`, `excludeCellularServices`, `excludeDeviceCommunication` from the policy, `enforceRoutes = false` |
| split tunnel | on | `includeAllNetworks = false`, `enforceRoutes = true` (the tunnel's routes can't be overridden by more specific local routes). The UI calls this **"Route protection"**, not "kill switch", and explains that non-tunnel traffic is not blocked. |
| any | off | `includeAllNetworks = false`, `enforceRoutes = false` |

Rules:
- `ProfileStore.updatePolicy` throws `.mustBeDisconnected` unless the manager's status is `.disconnected` or `.invalid`. The UI disables the toggles while connected, with an explanation.
- The policy is set when the manager is saved. **Every** connect path (window, menu bar, on-demand, System Settings) uses the same saved configuration, so policy cannot depend on the UI path (L-LC-4).
- With a kill-switch profile reasserting, traffic is expected to be blocked (fail closed; TBD-by-S2). The menu bar shows "Blocked — reconnecting".
- **Updates while blocked (L-KS-3):** see §12.3. The tunnel is stopped and on-demand disabled before the extension is replaced, then both are restored.
- **Built-in exclusions (SDK header, `NEVPNProtocol.h`):** with `includeAllNetworks`, the system **always** excludes "traffic necessary for connecting and maintaining the device's network connection, such as DHCP", "traffic necessary for connecting to captive networks", carrier-routed cellular services, and companion-device traffic. The leak harness pass criterion (§15.3) already allows DHCP/ARP/ND/RA. The captive-network exemption is undefined in scope (it presumably covers the system's captive probe and the Captive Network Assistant, not arbitrary browser traffic). S1 records what passes while a kill-switch tunnel is up or reasserting on a portal network, and LK-15 treats any such traffic as expected only if it matches that recorded set.
- **Assumption A-KS-1:** on macOS 27, `includeAllNetworks` with the exclude flags still permits AirDrop and Xcode device debugging (`excludeDeviceCommunication`), and blocks all other non-tunnel traffic, including the app's own (Sparkle). Spike S2 validates this. **Fallback:** document the exceptions and add a per-profile "compatibility" toggle that disables `includeAllNetworks` and uses `enforceRoutes`.

#### 10.1.1 What `includeAllNetworks` does when the tunnel ends (H1)

Draft 1 asserted these semantics. They are **not known**, and the Go app's behaviour must not be dropped silently. The Go kill switch (`internal/helper/firewall.go`) keeps a tunnel that **died unexpectedly** in `fwBlocked`: "blocked (fail closed, nothing passed but loopback/DHCP/ND) until the user disconnects or reconnects it, or turns the kill switch off". Only a user-initiated disconnect removes the rules.

Spike S2 measures on macOS 15, 26 and 27, with a kill-switch WG profile and a kill-switch OVPN-over-TCP profile:

| # | Event | Expected (TBD-by-S2) | What we measure |
|---|---|---|---|
| E1 | `kill -9` of the provider process | **blocked** while `nesessionmanager` restarts the provider (on-demand) or until the session is torn down; connectivity returns only after the system marks the session disconnected | time to `.disconnected`/`.reasserting`; packets on `en0` (BPF) during and after |
| E2 | `stopVPNTunnel()` from the app or `scutil --nc stop` | **open** immediately: this is a user stop | same |
| E3 | `cancelTunnelWithError` from the provider (fatal error) | unknown: open or blocked | same |
| E4 | reasserting (`reasserting = true`, no settings) | blocked | same |
| E5 | a **new** TCP connect (and, for the record, an ICMP echo) from the provider while connected, other than the tunnel transport | works (provider sockets are exempt) | connect success and time-to-first-byte, 50 trials. Mullvad reports (for iOS; unverified on macOS) that the provider's own TCP/ICMP sockets hang undetectably under the flag |
| E6 | OpenVPN over TCP: connect, 1 h of load, server-side reset → reconnect | works | no hang, no stall > 10 s |
| E7 | excluded host route to the endpoint (§8.5) | honoured or ignored; both are safe | routing table and behaviour |
| E8 | v4-only kill-switch profile with `allowLAN` and the §10.5 `::/0` blackhole: traffic to an on-link IPv6 host | LAN v6 still exempt (`excludeLocalNetworks`) | reachability of the LAN host; capture on `en0` |
| E9 | `saveToPreferences` of the **connected** manager with changed `onDemandRules`/`isOnDemandEnabled` only (the E1 keep-alive rule at connect, §10.4 changes, N5) | session keeps running, no restart | status transitions, session ID, packets during the save |

**LK-02 expected outcome (single):** after `kill -9` of the provider with the kill switch on, **no packet leaves a physical interface except to the VPN endpoint, until the user acts or the tunnel reconnects**. The status leaves `.connected` within 5 s. If S2 shows E1 fails open, LK-02 still expects this outcome, met by the app-level design below.

App behaviour for each possible S2 result:

| S2 result | Design |
|---|---|
| E1 blocked, E3 blocked | Matches the Go app, except that the Go app also allowed lifting the block by turning the kill switch off; here that needs Disconnect first (L-KS-2). `blockMode = .cancel` (§7.2): a fatal error cancels, and the system keeps blocking until the user disconnects. The UI shows "Blocked — <error>. Disconnect to restore internet." |
| E1 blocked, E3 **open** | `blockMode = .holdBlocked` (§7.2): on a fatal error with the kill switch on, the provider does **not** cancel. It stays alive in `reasserting` with the adapter stopped (code `.blockedAfterFailure`), which E4 shows to be blocking. The user ends it with Disconnect. This replicates `fwBlocked` for engine failures. |
| E1 **open** (provider death fails open) | We cannot block from a dead process. **Replicate fail-closed-on-death with on-demand.** Every kill-switch profile gets a `NEOnDemandRuleConnect(interfaceTypeMatch: .any)` while it is connected (saved at connect, removed on user disconnect). After a provider death, the system immediately restarts the provider, and `includeAllNetworks` blocks again from the moment the session is restarting. S2 measures the gap between death and re-block; the gap is documented and LK-02 allows packets only inside it (measured bound + 1 s). The user's Disconnect disables that on-demand rule first (§10.4 handles the interaction with Wi-Fi rules). If even on-demand restart leaves an unbounded gap, the regression is documented as below. |
| E5 hangs | `measureLatency` uses only the WG handshake RTT and OVPN's own transport stats, never a new provider-originated TCP connect while the tunnel is up; when disconnected it runs before any `includeAllNetworks` session exists. OVPN-over-TCP itself (E6) is a different case, because its socket is the tunnel transport. If E6 hangs, OVPN-over-TCP profiles with the kill switch get the compatibility toggle (`enforceRoutes` instead of `includeAllNetworks`) forced on, with a warning at import. |
| E2 blocked | The Disconnect action first saves the manager with `includeAllNetworks` unchanged but on-demand off, and waits for `.disconnected`. If traffic is still blocked, that is an OS bug. We report it as a known issue rather than toggling the flag (L-KS-2). |

**Regressions against the Go kill switch (user-facing, in the release notes and help):**
- The Go app also blocked when the **helper itself** was killed (pf rules persist in the kernel). The native app's equivalent depends on E1. If E1 is open and only the on-demand mitigation applies, a short leak window after a provider crash exists, and the help page states its measured length.
- The Go app's DNS protection (pf rules for port 53/853 outside the tunnel) has no separate switch: with `includeAllNetworks`, DNS follows the kill switch (§10.2).
- Split-tunnel "route protection" (`enforceRoutes`) does not block non-tunnel traffic, unlike the Go kill switch, which blocked everything except tunnels on any profile. This is shown in the UI (table above).

### 10.2 DNS (L-DNS-1, L-DNS-2, L-DNS-3)

`NetworkSettingsBuilder.dns(plan, policy, isFullTunnel)`:

| Case | `NEDNSSettings` |
|---|---|
| no servers | `nil` (system DNS). The import report warns for full tunnels ("DNS will go to your local resolver through the tunnel"). |
| full tunnel, any `dnsMode` | `servers`, `searchDomains = plan.searchDomains`, **`matchDomains = [""]`** (catch-all; NR §4 pitfall 12) |
| split, `.tunnelOnly` | the same, `matchDomains = [""]` |
| split, `.split` | `matchDomains = plan.splitDomains ∪ plan.searchDomains`. Domains only in `splitDomains` are resolved but not appended as search suffixes: `matchDomainsNoSearch = true` for that set. NE applies `matchDomainsNoSearch` per settings object, so when both kinds exist we keep `false` and also list the search domains in `searchDomains`. If the union is empty, `.split` falls back to `[""]` and the UI says so. |

- **L-DNS-1:** DNS is owned by the NE session. When the extension dies, the system removes the settings, so there is no journal. Test: `kill -9` the extension, then `scutil --dns` is back to baseline (§15.3, LK-11).
- **L-DNS-3:** `DNSVerifier` runs in the app, 3 s after every `.connected` and on demand in Diagnostics:
  1. Parse `scutil --dns` (spawned as the user, read-only) and `SCDynamicStoreCopyValue("State:/Network/Global/DNS")`.
  2. Expect resolver #1 to carry the plan's servers, and the tunnel interface to own the catch-all domain when the plan has `[""]`.
  3. Resolve a random label under `lockplus-check.invalid` through the system resolver and confirm the query completes.
  - The result is `.ok`, `.mismatch(details)` (an MDM profile or another VPN overrode it) or `.unknown(reason)`.
  - **`.unknown` is never shown as safe.** The banner says "Couldn't verify DNS" (the c9e9ffd lesson).
- The Diagnostics "DNS leak test" is the same verifier plus a list of the effective resolvers, each tagged tunnel or non-tunnel.
  - It never infers "leak" from a resolver answering, because with `includeAllNetworks` every resolver answers through the tunnel. The real leak test is the harness's capture on the physical interface.

### 10.3 DNS over HTTPS/TLS (cut from v2.0)

- v2.0 always uses plain `NEDNSSettings` to the profile's or the server's DNS servers. They are inside the tunnel, so confidentiality holds as far as the VPN server. The import report notes it when a profile asks for `transport DoH|DoT`.
- `NEDNSOverHTTPSSettings`/`NEDNSOverTLSSettings` as tunnel settings, and the former spike S3, move to §21.

### 10.4 Wi-Fi auto-connect (on-demand)

- macOS honours on-demand rules only on the **enabled** configuration, and only one packet-tunnel configuration is active.
- **Decision:** auto-connect designates **one** profile (`AutoConnectRules.profileID`). Its manager gets:
  ```swift
  let probes = [URL(string: "https://steiale.github.io/lockplus/probe.txt")!,      // ours, static, 200 "ok"
                URL(string: "https://www.apple.com/library/test/success.html")!]  // second host, different operator (N7)
  func connect(_ type: NEOnDemandRuleInterfaceType) -> [NEOnDemandRule] {        // one connect rule per probe host
      probes.map { let r = NEOnDemandRuleConnect(); r.interfaceTypeMatch = type; r.probeURL = $0; return r }
  }
  let trusted = NEOnDemandRuleDisconnect(); trusted.interfaceTypeMatch = .wiFi; trusted.ssidMatch = rules.trustedSSIDs
  let wifi = connect(.wiFi)
  let eth: [NEOnDemandRule] = rules.connectOnEthernet ? connect(.ethernet)
                              : [{ let r = NEOnDemandRuleIgnore(); r.interfaceTypeMatch = .ethernet; return r }()]
  let portal = NEOnDemandRuleIgnore();     portal.interfaceTypeMatch = .any   // both probes failed: likely captive portal
  manager.onDemandRules = [trusted] + wifi + eth + [portal]; manager.isOnDemandEnabled = rules.enabled && !paused
  ```
- `stayConnected` profiles get `connect(.any) + [portalIgnore]`.
- **Probe host dependency (N7).** A connect rule matches only when its probe returns HTTP 200 (`NEOnDemandRule.h`). If the probe host is down, blocked, or its TLS fails, the rule doesn't match, evaluation falls through to Ignore, and **auto-connect silently stops protecting** (fail open). Rules are evaluated in order, so a second connect rule with a probe on an independent host (Apple's HTTPS success page) matches when the first host is unavailable. Both probes are **HTTPS**: a portal that answers a hijacked plain-HTTP request with its own `200` login page would otherwise make the rule match; with HTTPS that request fails certificate validation. If both hosts are unreachable on a working network, the tunnel stays down: the app (if running) shows "Auto-connect couldn't verify this network" with a "Connect now" button, and its 15 s re-probe (below) tries both URLs. The help page documents both hosts and the fail-open case. The probe file on GitHub Pages must exist before the first beta (CI checks that it returns 200).

**Captive portals (M4).** On-demand plus `includeAllNetworks` would otherwise make hotel and airport login pages unreachable: on-demand connects on joining the network, the tunnel can't reach its server until the user has logged in, and the kill switch blocks the login page.
- `probeURL` on the connect rules: the rule only matches when the probe returns HTTP 200. On a captive network the probe is intercepted or redirected, so the connect rule does not match and evaluation falls through to the final **Ignore** rule. The tunnel stays down, the system's Captive Network Assistant appears, and the user logs in. The probes are static files on our GitHub Pages host and on apple.com; they carry no identifier and are fetched by the system, not by us. Their privacy note is in the help page.
- The `includeAllNetworks` header states that "traffic necessary for connecting to captive networks" is always excluded from the tunnel (§10.1). That does **not** make the rules above unnecessary: it is undocumented whether the exemption covers a browser login page or only the system's captive probe and CNA, and it does nothing for on-demand trying to connect before the login. S1 records what reaches the portal while a kill-switch tunnel is reasserting; if the CNA login works through the exemption on 15/26/27, "Pause protection" becomes a fallback rather than the main path for the already-connected case.
- After the login no network change happens, so on-demand may not re-evaluate (TBD-by-S1). The app (if running) watches `NWPathMonitor` and re-probes the same URL every 15 s for up to 10 min after joining a network where the connect rule didn't fire. When the probe succeeds, it calls `startVPNTunnel` on the auto profile. Without the app running, protection starts on the next network change. The UI states this.
- **"Pause protection for N minutes"** covers the case where the tunnel is **already up** (or reasserting/blocked) when the portal appears, e.g. after joining a new network while connected with the kill switch:
  - In the menu bar: "Pause protection ▸ 5 min / 15 min / 1 hour". The same entries appear in the "Blocked — reconnecting" banner, with the hint "Use this to log in to a Wi-Fi network".
  - Action: confirmation, "LockPlus will disconnect and allow unprotected internet for 15 minutes." Then `pausedUntil = now + N` and `pausedState = {profileID?, onDemandEnabledIDs}` in settings, register the resume agent (below), `isOnDemandEnabled = false` and save, then `stopVPNTunnel()`. The agent is registered **before** the tunnel stops, so a crash at any later point still resumes.
  - While paused, the menu-bar icon shows the warning badge with "Paused — 12 min left", and the menu offers "Resume protection now".
  - On expiry (an app timer, also checked on wake and launch): restore on-demand, and `startVPNTunnel` if the paused profile was connected. Then clear `pausedUntil` and unregister the agent.
  - If the app is quit while paused, the quit dialog defaults to "Resume protection and quit".
  - **A pause must not outlive a crashed app (N3).** The app bundles `Contents/Library/LaunchAgents/io.github.steiale.lockplus.mac.resume.plist` and registers it with `SMAppService.agent(plistName:)` for the duration of each pause:
    ```xml
    <key>Label</key><string>io.github.steiale.lockplus.mac.resume</string>
    <key>BundleProgram</key><string>Contents/MacOS/LockPlus</string>
    <key>ProgramArguments</key><array><string>LockPlus</string><string>--resume-protection</string></array>
    <key>StartInterval</key><integer>60</integer>
    <key>RunAtLoad</key><true/>
    <key>ProcessType</key><string>Background</string>
    ```
    - `LockPlus --resume-protection` is handled in `main.swift` before `NSApplicationMain`. It runs headless with no UI and exits within 5 s. If a regular LockPlus instance is running, it exits at once, because that instance's timer owns expiry. If `pausedUntil` is in the future, it exits. Otherwise it performs the expiry steps above with `NETunnelProviderManager` (same binary, same signature and entitlements), clears `pausedUntil`, calls `SMAppService.agent(plistName:).unregister()`, and exits.
    - `RunAtLoad` covers reboot and logout: the agent runs at the next login and resumes at once if the pause expired meanwhile. While the Mac is asleep, launchd coalesces missed `StartInterval` fires into one at wake.
    - **Why not `StartCalendarInterval` at `pausedUntil` (verified for draft 3):** `SMAppService.agent` accepts the standard launchd keys (`SMAppService.h`), but only for a plist **inside the signed app bundle**, so the plist is static and cannot carry a per-pause time. `StartCalendarInterval` is also a recurring calendar match (minute/hour/day…), not an absolute date. Writing a plist to `~/Library/LaunchAgents` with `launchctl bootstrap` would work, but it is the unmanaged LaunchAgent-plist path that NR §1 ("Login item" row) replaces with `SMAppService`. A static `StartInterval = 60` agent that checks `pausedUntil` is the closest public mechanism: expiry is honoured within 60 s even after a crash.
    - Registering may show the system's "Background item added" notification, and the user can disallow it in Login Items. If `status` is `.requiresApproval` or `register()` fails, the pause sheet says "If LockPlus quits unexpectedly, protection resumes the next time it opens", the previous launch-time behaviour.
  - Pause is never automatic.
- **Manual connect of another profile** makes it the enabled config, which suspends the auto profile.
  - When the user later disconnects it, the app (if running) re-enables the auto profile and restores its on-demand state.
  - The UI explains: "Auto-connect resumes when you disconnect Work".
- Disconnecting the auto profile from our UI while on-demand is active sets `isOnDemandEnabled = false` until the next network change: "Paused until you join another network". Otherwise on-demand would immediately reconnect.
- **SSID → specific profile map** (Go `SSIDTunnelMap`) is **cut from v2.0** (§21). Migration reports the Go map as "not migrated" (§13.1).
- On-demand keep-alive for kill-switch profiles: if S2 requires the E1 mitigation (§10.1.1), a connected kill-switch profile carries an `.any` connect rule while connected. When that profile is also the auto profile, its Wi-Fi rules take precedence, and the `.any` rule (with the same `probeURL`) is inserted after them and before the final Ignore rule. A user Disconnect turns on-demand off as described above.
- **Assumption A-OD-1 (NR Q1):** `ssidMatch` in on-demand rules is evaluated by the system without our app holding Location authorization. Spike S1 validates this, first with a `.mobileconfig` and then with our app.
  - **Fallback:** the app-assisted mode (CoreWLAN + Location) drives `startVPNTunnel`/`stopVPNTunnel` and on-demand toggling for all rules. It is documented as requiring the app to be running.
- Adding SSIDs: the user types them; "Add current network" needs Location and is optional.
- Profiles that need interactive auth cannot be the auto profile (§8.4).

### 10.5 IPv6 for v4-only full tunnels (M5)

A full-tunnel profile that assigns only IPv4 (WG `AllowedIPs = 0.0.0.0/0` without `::/0`; OVPN `redirect-gateway def1` without IPv6 settings) leaves the LAN's IPv6 default route in place. With the kill switch **on**, `includeAllNetworks` captures it (LK-09). With the kill switch **off**, every IPv6 destination goes around the tunnel.

**Decision (draft 3, N4; replaces draft 2's "whatever the kill-switch setting"):** the blackhole **follows the kill switch**. It applies to a v4-only full-tunnel profile when `killSwitch` is on (the default for full tunnels, §3.1), or when the per-profile toggle **"Block IPv6 without the kill switch"** (`blockIPv6WithoutKillSwitch`, off by default) is on. With the kill switch off and the toggle off, IPv6 goes to the LAN, exactly as in the Go app, which blocked v6 only with its kill switch on.
- Why not always: the blackhole drops silently (no ICMPv6 unreachable comes back), so clients **without** Happy Eyeballs (many CLI tools, some games, older SDKs) wait for a full connect timeout per AAAA address before falling back. And `::/0` into the tunnel also captures **LAN IPv6** (on-link ULA/GUA hosts, printers, NAS), which a user who turned the kill switch off usually wants reachable. Both costs are accepted where the user asked for strict protection, not otherwise.
- The toggle is policy (`NetworkPolicy`, mirrored as `providerConfiguration.blockIPv6`), so it obeys L-KS-2: it changes only while disconnected. The import report and Detail say which case applies: "IPv6 is blocked while connected (this profile tunnels IPv4 only)" or "IPv6 traffic bypasses the VPN (this profile tunnels IPv4 only; turn on the kill switch or 'Block IPv6' to prevent this)".

When it applies, `NetworkSettingsBuilder` routes `::/0` into the tunnel as a **blackhole**:
- `ipv6Settings` gets a unique local address (`fdxx:…/128`, derived from the profile UUID) and `includedRoutes = [::/0]`.
- WireGuard: wireguard-go drops packets that match no peer's AllowedIPs, so the IPv6 traffic dies inside the tunnel.
- OpenVPN: the shim makes the same plan when openvpn3 reports `block-ipv6` or no IPv6 settings. openvpn3's own `block-ipv6` handling (it also adds `block-ipv6` when `allowUnusedAddrFamilies == No`, `cliopt.hpp`) is honoured as the same blackhole.
- Effect: dual-stack apps fall back to IPv4 through Happy Eyeballs after the IPv6 attempt fails; other clients see the timeouts described above.
- With the kill switch on and `allowLAN`, `excludeLocalNetworks` is expected to keep exempting local IPv6 despite the `::/0` route; S2 records it (E8).
- Split-tunnel profiles are untouched: IPv6 not covered by the tunnel goes to the LAN by design.
- Tests: LK-09 in three variants (kill switch on; off; off with the toggle); §15.1 `NetworkSettingsBuilder` table test: the blackhole appears exactly when `isFullTunnel && !hasIPv6 && (killSwitch || blockIPv6WithoutKillSwitch)`.

---

## 11. UI architecture

### 11.1 App structure

```swift
@main struct LockPlusApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    var body: some Scene {
        Window("LockPlus", id: "main") { MainView().environment(delegate.env) }
            .defaultSize(width: 960, height: 640)
        Settings { SettingsView().environment(delegate.env) }
    }
}
```

- `AppDelegate` owns `AppEnvironment` (all stores) and `MenuBarController`.
- `NSApp.setActivationPolicy`:
  - `.regular` while a window is open;
  - `.accessory` when the last window closes;
  - the menu-bar app stays alive.
- On quit, `applicationWillTerminate` calls `NSStatusBar.system.removeStatusItem` (L-MB-1, 92a45b5).
- Navigation is a `NavigationSplitView` sidebar:
  - **Profiles** (list, with Detail and Editor);
  - **Statistics**;
  - **History**;
  - **Logs**;
  - **Diagnostics** (Latency, DNS check, Routes, Conflicts);
  - **Auto-Connect**.
- Settings window tabs: General (language, appearance, launch at login, menu bar rates, export all), Advanced (log level, new-profile defaults, uninstall, debug), About.
- Onboarding is a sheet on first launch:
  1. welcome;
  2. install the tunnel component (activation and approval);
  3. allow the VPN configuration (the first `saveToPreferences` triggers the system prompt);
  4. import, offering the Go migration (§13) if detected, file/zip/QR, or the `/etc/wireguard` scan (port of `scanner.go`);
  5. done.

### 11.2 State management

All stores are `@MainActor @Observable`. They are driven **only** by `NEVPNStatus` notifications and XPC results (L-LC-4).

| Store | Source of truth | Notes |
|---|---|---|
| `ProfilesStore` | `ProfileStore` actor + cached managers | `NEVPNConfigurationChange` → reload |
| `ConnectionStore` | `NEVPNStatusDidChange` per manager; `fetchLastDisconnectError` on `.disconnected` | Exposes `activeProfileID`, `status`, `lastError: LPErrorCode?` |
| `StatsStore` | XPC `statistics` polling (§7.7) | Owns the `RateMeter` |
| `ExtensionStore` | `SystemExtensionManager.state` + `hello` | |
| `AuthCoordinator` | `tunnelEvent(authRequired)` + `pendingAuthPrompt` | Single sheet; queues by promptID |
| `HistoryStore`, `SettingsStore`, `LogsStore`, `DiagnosticsStore` | files / XPC | |

- A connect click calls `session.startVPNTunnel(options: nil)`. The button shows "Connecting…" **only** because `NEVPNStatus` says `.connecting`. There is no optimistic UI state that can drift (7a6e365, cfc7fe9).

### 11.3 MenuBarController (L-MB-1)

```swift
@MainActor final class MenuBarController: NSObject, NSMenuDelegate {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    init(env: AppEnvironment) {
        item.behavior = .removalAllowed                 // respects user removal (isRemovalAllowed)
        item.autosaveName = "LockPlusStatusItem"
        menu.delegate = self
        item.menu = menu                                // native; no synthetic clicks, no event monitor (3f14acd)
    }
    func menuNeedsUpdate(_ menu: NSMenu) { rebuild() }  // always fresh: ◐ connecting, ● connected, auth needed (f83384f)
    func render(status: ConnectionSnapshot, rate: Rate?)  // icon + label
}
```

- Icon: 18 pt template images, designed for the 30 pt Tahoe menu bar.
  - Idle: a template padlock.
  - Connected: the padlock with a filled badge.
  - Warning (reasserting, blocked, auth needed): a badge with "!".
  - Color is never the only signal (accessibility). The design reuses the v1.0.61 icons, re-exported as PDF/SF-Symbol-style templates.
- Rate label: `button.attributedTitle` uses `NSFont.monospacedDigitSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)`. The format is `↓1.2M ↑30K` with a fixed-width unit formatter, so it never jitters (2d08dc8).
- `RateMeter` implements the baseline rule:
  ```swift
  struct RateMeter {
      private var baseline: (rx: UInt64, tx: UInt64, t: ContinuousClock.Instant)?
      mutating func ingest(rx: UInt64, tx: UInt64, at t: ContinuousClock.Instant) -> Rate? {
          guard let b = baseline else { baseline = (rx, tx, t); return nil }
          let dt = (t - b.t).seconds; guard dt >= 0.5 else { return nil }   // bytes AND time skip together
          defer { baseline = (rx, tx, t) }                                    // commit together, one assignment
          return Rate(down: Double(rx &- b.rx) / dt, up: Double(tx &- b.tx) / dt) // counter reset → treat as 0
      }
  }
  ```
- Visibility: observe `item.isVisible`. If the user or System Settings › Menu Bar ("Allow in the menu bar", macOS 26+) hides the item, Settings shows "The menu bar icon is hidden" with instructions, and the app opens its main window on launch so it stays reachable.
- Menu contents:
  - the status line;
  - each profile (connect/disconnect toggle, with the active one checked, ◐ while connecting);
  - "Authentication required…" when pending;
  - "Pause protection ▸ 5 min / 15 min / 1 hour" when a kill-switch or auto-connect profile is active, or "Resume protection now (12 min left)" while paused (§10.4; expiry is enforced by the resume agent even if the app is gone);
  - "Open LockPlus", "Settings…", "Quit LockPlus".
  - Quit asks first if a tunnel is connected: "The tunnel stays connected after quitting. Disconnect?" — Keep / Disconnect / Cancel. While paused, quit asks "Resume protection and quit" (default) / "Quit and stay paused" / Cancel; "stay paused" leaves the resume agent registered, so the pause still ends on time.

### 11.4 Editor

- An `NSTextView` in `NSViewRepresentable`, with TextKit 2.
- Disabled: smart quotes, dashes, text replacement, spell checking and automatic link detection. Smart quotes would corrupt configs. Font: monospaced.
- Syntax highlighting is a `ConfigHighlighter` driven by **our own parsers**, run on a background task with a 150 ms debounce, so the colors exactly match what import will accept:
  - WG: section headers, known keys, values, comments, ignored keys (dimmed with a tooltip).
  - OVPN: directive names colored by `EngineSupport` class (mapped / ignored / forbidden underlined in red), inline tags, comments.
- Diagnostics: `ValidationIssue`s appear as line annotations in a gutter and a list under the editor. Save stays disabled while there are errors.
- No web view. CodeMirror is not carried over.
- Opening the editor of an existing profile requires `LAContext` (A6). The new-profile editor does not.

### 11.5 Other views (parity map)

| Go component | Native view | Notes |
|---|---|---|
| `TunnelCards.svelte` | `ProfileListView` + `ProfileDetailView` | Detail: status, endpoint, protocol, assigned addresses, cipher (OVPN), last handshake (WG), transfer, MTU, policy toggles, import report |
| `StatsDashboard.svelte` | `StatisticsView` (Swift Charts, 5 min rolling rx/tx) | Data from `StatsStore` |
| `History.svelte` | `HistoryView` (Table, filters, clear) | |
| `LogViewer.svelte` | `LogsView` | Merged app `OSLogStore(scope: .currentProcessIdentifier)` + extension ring via `recentLogs` |
| `DNSLeakTest.svelte` | `DNSCheckView` | §10.2 |
| `RouteVisualization.svelte` | `RoutesView` | sysctl `NET_RT_DUMP2`, read-only, no root |
| `ConflictWarning.svelte` | `ConflictsView` + banner | Other utun interfaces with default routes; Go helper (§4.5) |
| `WifiRules.svelte` | `AutoConnectView` | §10.4 |
| `Onboarding.svelte` | `OnboardingSheet` | |
| `Settings.svelte` | `SettingsView` | |
| `UpdateNotice.svelte` | Sparkle standard UI | |
| `KofiBanner.svelte` | `SupportBanner` | dismissible |
| Latency | `measureLatency` XPC | WG: the handshake RTT (forced handshake). OVPN while connected: the engine's keepalive round trip if openvpn3 exposes one, otherwise "—". OVPN while disconnected: a TCP connect for `proto tcp` endpoints, made before any `includeAllNetworks` session exists (§10.1.1 E5). **Only to the profile's own endpoints** (no probe oracle). ICMP from the root extension is cut (§21). |

### 11.6 Localization and accessibility

- `Localizable.xcstrings` and `InfoPlist.xcstrings`, en (source), de, ko, ja.
  - A one-off script seeds the catalogs from `frontend/src/i18n/*.json` (201 keys) through a mapping table. It is committed, not run at build time.
  - Error codes map to `LocalizedStringResource` in the app only.
- Language override: Settings writes `UserDefaults.standard.set([code], forKey: "AppleLanguages")` and applies it after a restart. "System" removes the key.
- Accessibility:
  - every control has a label; the status item's `accessibilityLabel` reads "LockPlus, connected to Work, down 1.2 megabytes per second";
  - state is never conveyed by color alone;
  - full keyboard navigation (⌘1–⌘6 for sidebar sections, ⌘N import, ⌘E edit, ⌘K connect/disconnect);
  - Reduce Motion is honoured in charts;
  - VoiceOver rotor headings in Detail.

### 11.7 Error surfacing (L-OVPN-4)

- Every terminal tunnel error reaches the UI through `fetchLastDisconnectError` (or the `tunnelSnapshot.lastError` fallback).
- It is shown as an inline banner in Detail and in the menu-bar status line, with a localized message and a "Details…" disclosure (code, time, the extension's non-secret detail).
- Import, provision and XPC errors appear as sheet alerts. Background failures (reconcile, history sync) appear in a "Problems" list in Diagnostics, never as modal spam.

---

## 12. Updates and distribution

### 12.1 Sparkle 2 configuration (L-UPD-1)

- Sparkle ≥ 2.9 via SPM, in the app only.
- An EdDSA key pair is generated once with `generate_keys` on the dev Mac.
  - **The private key never enters CI (M1), and neither does anything else that makes a release (N1).** The EdDSA key lives in the dev Mac's login keychain, where `generate_keys` stores it, with an offline backup in 1Password. The Developer ID identity, both Developer ID provisioning profiles and the `notarytool` keychain profile live there too. Alex runs `Tools/release/release.sh <tag>` on the dev Mac, which builds, signs, notarizes and EdDSA-signs in one place (§12.4), then publishes the appcast to gh-pages: first to the `rc` channel only, then, after the release gates (§12.4) are green, to everyone.
  - Why: Sparkle accepts an update that changes the Apple code-signing identity whenever the EdDSA signature validates (Sparkle's documented key-rotation rule). The EdDSA key is therefore the **only** thing standing between a compromise and every user (§1.3 A5). Keeping the key off CI is not enough on its own: draft 2 had CI build and notarize the artifacts that the dev Mac then signed, so a CI compromise could have had a malicious build EdDSA-signed by the dev Mac. Now nothing CI produces is ever signed.
  - **Releases fail hard without it**: `release.sh` exits non-zero if the key is missing, and there is no "grace mode".
  - **Key rotation needs a DMG enclosure (N1).** With `SUVerifyUpdateBeforeExtraction = YES`, Sparkle allows a new EdDSA key only in a Developer ID code-signed **disk image**. Regular items stay zips; the rotation release uses the signed, notarized DMG from §12.2 as its enclosure (§1.3 A5). `release.sh --rotate-key` produces that item.
  - Blast-radius limits if it leaks anyway (§1.3 A5): the XPC requirement pins team `M53GHX9FAY` and Developer ID (§5.3), so a foreign-team app cannot reach the extension; the system only replaces a system extension with one from the same team; and the data-protection keychain items are bound to our team's access group.
- Appcast: `https://steiale.github.io/lockplus/appcast.xml` (GitHub Pages, HTTPS).
  - Archives: `LockPlus-<ver>.zip` on GitHub Releases.
  - `SURequireSignedFeed = YES` with `SUVerifyUpdateBeforeExtraction = YES`.
  - The feed signature is generated by `generate_appcast`.
- No custom download host logic, so the redirect-host problem (8f578a8) disappears. Sparkle validates the archive signature regardless of host.
- Downgrades:
  - Sparkle offers only versions higher than the running one;
  - our `SPUUpdaterDelegate.bestValidUpdate(in:for:)` additionally filters items whose `CFBundleVersion` is less than or equal to ours;
  - the extension refuses downgrade replacement (§4.2).
  - A user who deliberately installs an older version uses "Reinstall tunnel component" (§4.6). There is no silent rollback path.
- Deltas are enabled (`generate_appcast` default, keeping 3 prior versions).
- **Channels:** the appcast has the default channel plus `rc`, using Sparkle's `sparkle:channel` and `SPUUpdaterDelegate.allowedChannels(for:)`. Settings › Advanced has "Receive release candidates" (off by default). The leak harness and update tests use this shipped mechanism to pull a release candidate (§15.3, §15.5); no test-only feed override exists in the binary.

### 12.2 Distribution artifacts

- `LockPlus-<ver>.zip` (for Sparkle and the cask) contains exactly `LockPlus.app`. The beta channel uses `LockPlus Native.app` (§13.4). CI asserts the top-level name (L-DIST-1).
- `LockPlus-<ver>.dmg` is made by `create-dmg` with an Applications symlink, then Developer ID-signed, notarized and stapled (on the dev Mac, §12.4). It is the manual-download artifact and, for a key rotation only, the Sparkle enclosure (§12.1).
- Homebrew cask `lockplus-native` during beta, `lockplus` after cutover:
  ```ruby
  cask "lockplus" do
    version "2.0.0"; sha256 "…"
    url "https://github.com/steiale/wireguide/releases/download/v#{version}/LockPlus-#{version}.zip"
    name "LockPlus"; homepage "https://github.com/steiale/wireguide"
    auto_updates true
    depends_on macos: ">= :sequoia"; depends_on arch: :arm64
    app "LockPlus.app"
    uninstall script: { executable: "#{appdir}/LockPlus.app/Contents/MacOS/LockPlus",
                        args: ["--uninstall-system-components"], sudo: false, must_succeed: false },
              quit: "io.github.steiale.lockplus.mac"
    zap trash: [
      "~/Library/Application Support/io.github.steiale.lockplus.mac",
      "~/Library/Preferences/io.github.steiale.lockplus.mac.plist",
      "~/Library/Caches/io.github.steiale.lockplus.mac",
      "~/Library/HTTPStorages/io.github.steiale.lockplus.mac",
      "~/Library/Saved Application State/io.github.steiale.lockplus.mac.savedState",
    ]
  end
  ```
- **Zap audit (L-DIST-1):**
  - the native zap never lists `~/Library/Application Support/lockplus` or `wireguide-plus`;
  - the `lockplus` (Go) and `wireguide-plus` cask zaps are re-audited at cutover so they never list `io.github.steiale.lockplus.mac` paths;
  - CI greps every cask file in the tap for cross-references.
- Brew detection, if any (e.g. "updates are managed by Homebrew"): check the absolute paths `/opt/homebrew/Caskroom/lockplus*` and never shell out without a full PATH (15b0d2a).
  - **Decision:** with `auto_updates true`, Sparkle stays enabled for cask users too.

### 12.3 Update flow with extension re-activation (L-UPD-1, L-KS-3, L-EXT-3)

1. Sparkle downloads and verifies the update (through the tunnel if connected; that is fine).
2. `SPUUpdaterDelegate.updater(_:shouldPostponeRelaunchForUpdate:untilInvokingBlock:)` → `UpdateCoordinator.prepareForInstall`:
   1. Write `pendingResume = {profileID, onDemandEnabledIDs, reason: .extensionUpdate}` to `settings.json`, with the same contents as §4.2 step 3.1.
   2. Set `isOnDemandEnabled = false` on **every** owned manager that has it on, and save each, exactly as §4.2 step 3.2 does. The auto profile alone isn't enough: a `stayConnected` profile or a kill-switch profile carrying the §10.1.1 E1 keep-alive rule could otherwise restart the old extension mid-replacement (N5).
   3. `stopVPNTunnel()` and wait for `.disconnected` (15 s timeout; on timeout continue anyway, logged). Kill-switch blocking ends here, so **the Mac is online during the replacement**.
   4. Invoke the block; Sparkle installs and relaunches.
3. The new app launches and calls `activate()`. Its preflight (§4.2 steps 2–3) finds the old extension enabled and the tunnel already quiesced (step 2 above), so step 3 is a no-op. The request is submitted, and `actionForReplacingExtension` returns `.replace` by pure comparison. On `.completed`, the app connects to the new versioned Mach name and runs `hello` and `reconcile`.
4. `UpdateCoordinator.resumeAfterUpdate()` restores on-demand on every manager in `pendingResume.onDemandEnabledIDs` and calls `startVPNTunnel` for `pendingResume.profileID`, then clears `pendingResume`.
5. If activation needs approval or a reboot: on-demand stays restored but the tunnel can't start. The UI shows the approval/reboot dialog. With a kill-switch profile, nothing is blocking in the meantime (the tunnel is off), and the UI says so explicitly: "Not protected until the update finishes".
6. The **first launch after any update** always runs `activate()` (L-EXT-2), so even an update installed by brew or by drag-replace without Sparkle replaces the extension. In those cases the §4.2 preflight does the quiescing (stop and on-demand off) that step 2 would have done, then resumes.

### 12.4 CI (GitHub Actions)

Workflows (`.github/workflows/native-*.yml`), path-filtered on `native/**`:

| Job | Runner | Steps |
|---|---|---|
| `lint` | macos-26 (Xcode 27) | swift-format lint, SwiftLint (custom rules: no secret interpolation in Logger, Backoff required, no `exit(` in Tunnel/), `version-check.sh` |
| `unit` | macos-26 | `swift test` for LockPlusCore/TunnelEngine; `xcodebuild test -testPlan Unit` |
| `fuzz-smoke` | macos-26 | `swift build -c release -Xswiftc -sanitize=fuzzer,address` for the LPParsing targets, and clang `-fsanitize=fuzzer,address` for the `OpenVPN3Options` parse target; 10 min per target; corpus cached |
| `engine-support` | macos-26 | regenerate `OVPNEngineSupport.generated.swift` against the pinned openvpn3 and diff (§8.2); symbol check that no `tun/mac/client` code is linked (§8.1) |
| `build-dev` | macos-26 | Release-configuration build, **ad-hoc signed** (`CODE_SIGN_IDENTITY=-`, no provisioning profiles), `otool -L` extension check (no AppKit/SwiftUI/Sparkle), entitlement dump diff against golden files (ad-hoc signatures still embed entitlements), no `debugInjectFault` symbol. No secrets. |
| `repro` (tag `native-v*`, optional) | macos-26 | Builds the tag unsigned (`CODE_SIGNING_ALLOWED=NO`, fixed DerivedData path, `-debug-prefix-map`) and publishes the SHA-256 of every Mach-O in the bundle as a workflow artifact. No secrets, no release artifact. |
| Release build | **dev Mac**, `Tools/release/release.sh native-vX.Y.Z` | Refuses to run unless: the working tree is a **fresh clone** of the tag into a new directory under `~/Code/lockplus-release/`, the tag is signed (`git tag -v`), `git status` is clean, and `version-check.sh` passes. Then: archive, `-exportArchive` (method `developer-id`, manual signing, both profiles), verify (`codesign --verify --deep --strict`, golden entitlements, no `debugInjectFault`), notarize (`notarytool submit --wait --keychain-profile …`), staple, zip + dmg, notarize and staple the dmg, upload to a **draft** GitHub Release with SHA-256s. Optionally compares the pre-signing Mach-O hashes with the `repro` artifact; a mismatch is reported (non-gating until two clean builds of the same tag are shown to match). |
| Stage RC | dev Mac, `Tools/release/release.sh --stage-rc` | EdDSA signing (`sign_update`) of the artifacts it built itself (the script refuses artifacts it didn't build in this checkout) and `generate_appcast`. The item is added with `sparkle:channel rc` only, so default-channel users never see it. |
| `leak-harness` | self-hosted `macdev` (real NIC, Wi-Fi + Ethernet), environment `release-gate` | §15.3 against the RC (installed from the draft DMG; LK-10 updates N-1 → RC via the `rc` channel). Required for promotion. |
| Upgrade test | manual, on a VM snapshot or a spare Mac (§15.5) | N-1 → RC via the `rc` channel; the checklist result is attached to the draft release. Required for promotion. |
| Promote | dev Mac, `Tools/release/release.sh --promote` | Removes the channel tag from the item (same signed archive, re-generated and re-signed feed), pushes gh-pages, and un-drafts the release. Refuses to run unless both gates are recorded as passed. |

- **CI holds no signing material (N1):** no Developer ID certificate, provisioning profile, App Store Connect API key or EdDSA key in repository or environment secrets. The `release` environment from draft 2 is removed. §15.6 checks this on every release.
- The dev-Mac release is the cost of N1: releases depend on that machine (§20 risk 9). The checkout is a fresh clone per release, never the working copy, so local uncommitted changes or a stale build folder can't end up in a release.
- Credential check: the notarization step first runs `xcrun notarytool history --keychain-profile …`. It is never checked with `security find-generic-password` (L-DIST-2).
- **Xcode 27 export (L-DIST-2, NR Q9):** `xcodebuild -exportArchive` with an `ExportOptions.plist` (`method = developer-id`, `signingStyle = manual`, `provisioningProfiles` for both IDs).
  - Validation:
    - `spctl -a -vv -t exec`;
    - `codesign -d --entitlements :-` on both bundles, compared to golden files;
    - a smoke activation on the test VM or spare Mac.
  - **Fallback** if S9 fails: `Tools/release/resign-inside-out.sh` (vendored, reviewed) signs the extension first, then the app, with explicit entitlements files.

---

## 13. Migration from the Go app (L-MIG-1)

### 13.1 Copy-only importer (native app)

`GoAppMigrator` runs during onboarding, or later from Settings › Advanced › "Import from old LockPlus…".
1. **Detect:** `~/Library/Application Support/lockplus/tunnels/`. Also look in `…/wireguide-plus/tunnels/` if the former is empty (the v1.0.62 precedent).
2. **Enumerate:**
   - `*.conf` → WG;
   - `*.ovpn` → OVPN (`.ovpn` presence is authoritative, as in Go `LoadMeta`);
   - `<name>.meta.json` → `{auto_reconnect, notes, protocol}`.
   - Skip dotfiles, `*.tmp`, `*.corrupt.*` and symlinks (`lstat`).
3. **Per tunnel:** run the native import pipeline (§8.1/§9.1) on the file bytes. The result is ✔ imported (new UUID), ⚠ imported with an import report, or ✖ rejected with the reason. The display name is the old file name.
   - Old names like `work.vpn` that the Go rules rejected are still valid display names now.
4. **Policy:** from `config.json`:
   - `kill_switch` → `killSwitch` for full-tunnel profiles (route protection for split);
   - `dns_protection` → `dnsMode = .tunnelOnly`;
   - `auto_reconnect` → `stayConnected = false` (the extension always reconnects), with a note.
5. **Credentials:** §6.7, opt-in.
6. **Settings:**
   - `language` (`auto` → `.system`), `theme` → appearance, `log_level`;
   - `onboarding_complete = true`;
   - `auto_start` → offer "Launch at login?" (we never auto-register; NR §4 pitfall 14);
   - `kofi_dismissed`.
7. **Wi-Fi rules** (`wifi_rules.json`):
   - `enabled`, `trusted_ssids`;
   - `default_tunnel` + `auto_connect_untrusted` → auto profile (by name → UUID);
   - `ssid_tunnel_map` is **not migrated** (`ssidProfileMap` is cut, §21). The migration report lists it: "Per-network profile choices aren't supported yet".
8. **History** (`history.json`): each session becomes a `HistoryEntry` with a new UUID, `profileID` by name match (nil if none), and `endReason` mapped from `disconnect_reason`.
9. **Marker:** `migration.json = {completedAt, source: path, items: [{oldName, newID, digest, result}]}`. Automatic migration runs only when no marker exists. A manual re-run dedupes by payload digest. **Nothing in the Go directories is ever written, moved or deleted.**

### 13.2 Coexistence period

Both apps can be installed: different bundle IDs, app names, data directories and keychain services (§4.5 rules apply).

### 13.3 The Go app's final release (v1.2.0 "Farewell")

Added to the Go codebase (Go release line, Fable security review mandatory):
- On launch, a dialog: "LockPlus has a new version. Your tunnels will be copied by the new app. Remove the old helper now?"
- **"Remove"** calls a new helper RPC, `Uninstall`, which runs as root:
  1. Disconnect all tunnels (stop openvpn, close utun).
  2. Flush pf anchors `com.apple/wireguide` and `com.apple/wireguide/dns`.
  3. Restore the pf enable state from `pf-was-enabled`.
  4. Restore DNS from `dns-journal.json` (the existing journal-restore code path).
  5. Remove `/Library/PrivilegedHelperTools/io.github.steiale.lockplus.helper` and `/Library/PrivilegedHelperTools/openvpn`, `/Library/LaunchDaemons/io.github.steiale.lockplus.helper.plist`, `/var/run/lockplus`, and `/Library/Application Support/lockplus`.
  6. `launchctl bootout system/io.github.steiale.lockplus.helper` as the last step, from a detached child.
- **Caller authentication, stated:** the Go IPC server authenticates peers by **uid only** (`LOCAL_PEERCRED` → `verifyPeerUID`, `internal/ipc/peercred_*.go`), with no code-signature check. Any process running as the GUI user can therefore call `Uninstall`. The impact is **denial of service only**: it disconnects the Go tunnels, removes the Go kill switch, restores DNS and removes the helper. No secret is read and nothing is executed with attacker input. Same-user malware can already disrupt the Go app (`kill`, socket floods), so this is accepted and not hardened in a release whose purpose is removal. The Fable review checks that the RPC takes **no arguments** (no paths, no names) so this stays true.
- The GUI then removes its LaunchAgent and login item and shows "Install LockPlus 2" with the download link and the cask command.
- It does **not** delete `~/Library/Application Support/lockplus` or the legacy keychain items, so a later re-migration stays possible. The user can delete them from the native app (Settings › Advanced › "Remove old LockPlus data…", with confirmation, LAContext, and only after a completed migration marker).
- The custom Go updater serves v1.2.0 as its last update.

### 13.4 Cask transition

1. Beta: the native cask `lockplus-native` installs `LockPlus Native.app`, and the Go cask `lockplus` stays. Both zaps are scoped (§12.2).
2. Cutover:
   - publish Go v1.2.0 (cask `lockplus` 1.2.0);
   - wait 2 weeks;
   - switch the `lockplus` cask to the native 2.x artifact (`LockPlus.app`). Its `uninstall` runs `--uninstall-system-components` for the native app only.
   - `caveats` say: "If you used LockPlus 1.x, open it once to remove its helper (or run `…/LockPlus.app/Contents/MacOS/lockplus --uninstall-helper` before upgrading)."
3. `lockplus-native` is deprecated with `deprecate! because: "renamed to lockplus"`. Beta users keep the `LockPlus Native.app` path, and Sparkle updates it in place.
4. The wireguide-plus cask's zap is re-audited.

---

## 14. Observability

### 14.1 OSLog

| Subsystem | Categories |
|---|---|
| `io.github.steiale.lockplus.mac` | `lifecycle`, `extension`, `xpc`, `profiles`, `import`, `keychain`, `connection`, `menubar`, `update`, `migration`, `diagnostics`, `ui` |
| `io.github.steiale.lockplus.mac.tunnel` | `lifecycle` (incl. "first light" in `main.swift`, L-EXT-6), `xpc`, `controller`, `engine.wg`, `engine.ovpn`, `auth`, `dns`, `path`, `watchdog`, `secrets` |

Privacy rules:
- Interpolate only enums, state names, error codes, durations, counts and UUIDs as `.public`.
- Hostnames, IPs, SSIDs, usernames, profile names and challenge text are `.private(mask: .hash)`.
- Secrets are **never** passed to `Logger`; the `SecretBytes` type makes it impossible by accident.
- Server-controlled strings are `.private` and length-capped at 256.
- In addition, the extension writes redacted records into an in-memory ring (2000 entries) for `recentLogs`. The app does not need OSLogStore privileges to read the extension's logs.

### 14.2 Diagnostics bundle

Settings › Advanced › "Export diagnostics…" (LAContext not required, because the bundle has no secrets) writes a zip (0600, `O_NOFOLLOW`) containing:
- `system.json`: macOS version, model, app and extension versions, extension state (`propertiesRequest`), SIP status;
- `profiles.json`: profile metadata with names **hashed**, endpoints replaced by `host#hash:port`, policies, import reports;
- `ne-configs.json`: manager summaries (flags, on-demand rules with SSIDs hashed), never `providerConfiguration` raw values beyond the policy keys;
- `logs-app.txt` (last 24 h, `OSLogStore(scope: .currentProcessIdentifier)`) and `logs-tunnel.txt` (ring);
- `dns.txt` (`scutil --dns` with IPs kept, search domains hashed), `routes.txt`, `history-summary.json` (counts only);
- `legacy.json` (§4.5 findings).

`Redactor` is a pure, unit-tested function with corpora of keys, passwords, CRV1 cookies, auth-tokens and PEM blocks. A test runs it over the full bundle of a fixture system and asserts that none of the planted secrets appear.

---

## 15. Testing strategy

### 15.1 Unit (LockPlusCore, TunnelEngine)

- **OVPN tokenizer:** port every case of `internal/ovpn/validate_test.go`, `ovpn27_test.go` and `realprofiles_test.go`:
  - quotes, single quotes, backslashes;
  - inline close tags with trailing text;
  - `<connection>` re-parse and nesting rejection;
  - BOM, NUL, 256-character lines, 16-parameter truncation;
  - `--` prefixes;
  - `setenv opt` recursion.
  - The Go test vectors are exported as JSON fixtures by a one-off Go test helper committed to the Go tree, so both implementations run the **same** vectors.
- **Allowlist:** every rule, every rejection message (directive name only, no args).
- **Differential (L-OVPN-1):**
  1. Swift tokenizer vs `OpenVPN3Options` on the corpus (unit) and under fuzzing (§15.4). A mismatch on canonical output fails.
  2. Canonical → openvpn3 → re-serialize is the identity.
  3. The Go 2.7 tokenizer vs the Swift port on the shared fixtures. Equality is required.
- **EngineSupport:** covers exactly the allowlist; the regenerated table equals the committed one (§8.2); the canonical caps (256 KiB, 512-byte lines, 64-char names) reject at the boundary +1.
- **Metadata HMAC:** a flipped bit in any field → quarantine; a missing payload-key item with files present → "locked" UX and no key is generated (§6.8); an older validly MAC'd file (lower `metaRevision` or `payloadRevision` than the manager's `providerConfiguration`) → quarantine, and the manager is not re-saved (§3.4, N6).
- **RevealGate:** every code path to `ProfileStore.payload(for:)` from UI code goes through `RevealGate` (a test enumerating the call sites via a protocol witness, §1.3 A6).
- **Activation preflight:** a table test of `propertiesRequest` results × manager states → quiesce/submit/refuse decisions (§4.2); the replacement delegate is a pure function.
- **WG parser and validator:** port `parser_test.go` and `validator_dns_test.go`; add wg-quick inline-comment, bare-IP and CRLF cases.
- **Legacy keychain decode:** b64, hex and plain fixtures (`keychain_darwin_test.go` vectors).
- **NetworkSettingsBuilder IPv6:** the `::/0` blackhole appears exactly when `isFullTunnel && !hasIPv6 && (killSwitch || blockIPv6WithoutKillSwitch)` (§10.5, N4).
- **Shim fd ownership:** `tun_builder_establish` never returns the provider's fd number, and closing what it returned leaves the provider's fd valid (`fcntl(F_GETFD)`), §7.3 (N2).
- **Resume agent:** `--resume-protection` with `pausedUntil` in the future, in the past, absent, and with a running app instance → no-op / resume + unregister / unregister / exit (§10.4, N3).
- **DNS mapping:** a table test of `DNSPlan` → `NEDNSSettings` for each §10.2 row; the pull-filter vectors from `config.go` `filterPushed`.
- **State machine:** `TunnelController` with `FakeAdapter`, `FakeHost`, `TestClock`, `FakePathWatcher`. One test per transition row in §7.2, plus:
  - completion called exactly once;
  - `fatal` → `cancel` within one tick (L-LC-1);
  - auth pauses the connect deadline (L-RC-4);
  - a stale `promptID` is rejected;
  - backoff caps and resets (L-RC-3);
  - kill switch on → never cancels on budget exhaustion;
  - sleep → wake → reasserting → connected (L-RC-5).
- **RateMeter:** a burst of sub-500 ms samples does not move the baseline (L-MB-1); counter reset.
- **XPC wire:** size limits, unknown fields, version mismatch, timeouts with a fake connection, late replies ignored.

### 15.2 Integration (on a signed dev build, self-hosted Mac)

- Activation outcomes: approval needed (fresh VM), replace, downgrade refused, `.unsupportedParentBundleLocation` (app run from `~/Downloads`).
- XPC peer validation: an unsigned client, a team-signed client with the wrong identifier, and the right one.
- Extension secret store: provision, read at connect, update, delete, `wipeAll`. Files are root 0600 in a 0700 dir; a planted symlink in `secrets/` is refused. Secrets stay readable after an extension update and after a reboot (before and after login, with the S4 key-wrap choice) (S4).
- Activation preflight (§4.2): drag-replace and `brew upgrade` with the app closed and the tunnel up → on launch the tunnel is stopped before the request, replaced, and resumed. "Reinstall tunnel component" from N to N-1 (§4.6).
- Captive portal (§10.4): a test AP with a portal (a small Linux VM serving a 302) → no on-demand connect, CNA appears, the app connects after the probe succeeds; "Pause protection" round trip; the same with the first probe host blackholed (the second rule connects); pause, then `kill -9` the app and reboot before expiry → the resume agent resumes at login (N3, N7).
- WG against a test server (docker on a VPS): connect, data-plane-up timing, endpoint failover (first A record blackholed), MTU applied (`ifconfig utunN`).
- OVPN against test servers:
  - UDP, TCP, tls-crypt-v2;
  - CBC-only (`cipher AES-256-CBC`, no NCP);
  - BF-CBC;
  - password, SC (SCRV1 and concat), CRV1 (a server that issues a CRV1 with a username), AUTH_FAILED → re-prompt;
  - an OTP profile on a server **without** `auth-gen-token`: force a reconnect (`ping-restart`) → a prompt appears and the server log shows no login attempt with the stale OTP (M6); the same with `auth-gen-token` → silent reconnect;
  - a profile with each openvpn3-fatal directive class (server-only, push-only, removed, `management*`, unknown) → rejected at **import** by [7b], never at connect;
  - WEB_AUTH → `.webAuthUnsupported` within 2 s;
  - a server pushing `dns server`, `dhcp-option`, PUSH_UPDATE, plus profile `pull-filter ignore "dhcp-option"`.
- **Real profiles (spike gate and regression):** BHP (Sophos) and AllService, run manually on each release candidate. Credentials are never in CI.
- L-LC-1: close the wireguard-go device via `debugInjectFault(.wgDeviceClose)` → status leaves `.connected` ≤ 5 s.
  - **Fault injection lives only in a separate `FaultInjection` build configuration** (its own scheme and its own compile flag `LP_FAULT_INJECTION`; never archived for release). CI's `build-dev` and the dev-Mac `release.sh` both assert that the Release binary contains no `debugInjectFault` symbol.
  - These tests are **non-gating** for releases: they verify engine logic, not the shipped binary. The release gates (§15.3) use only the shipped RC.

### 15.3 Leak harness (L-KS-1, L-KS-4, L-DNS-1)

`Tools/leak-harness/lp-leakcheck`:
- runs as root on the self-hosted Mac;
- tests the **shipped release candidate**, i.e. the notarized build from the draft release, exactly as users get it. There is no automation XPC and no DEBUG hook (M3);
- drives it only through interfaces that exist in the shipped product:
  - `scutil --nc list/start/stop/status "<name>"` for connect, disconnect and status (it works on any NE configuration by name);
  - fixtures are imported once per machine through the shipped file-open path (`open -a LockPlus fixture.conf`) and confirmed in the UI. Each policy variant is a separate pre-imported profile (`wg-ks`, `wg-noks`, `ovpn-tcp-ks`, `wg-split-rp`, `wg-v4only-noks`, `wg-v4only-noks-block6`, …), so the harness never toggles policy;
  - root-level OS actions: `pkill -9 -f io.github.steiale.lockplus.mac.tunnel`, `pmset`, `networksetup`, `route`/test-router rules;
  - Sparkle through the shipped `rc` channel (§12.1) for LK-10;
- captures on the physical interfaces (`en0` Wi-Fi, `en7` USB Ethernet) with BPF.
- Fault injection (`FaultInjection` build, §15.2) is a separate, non-gating suite.
- **Pass criterion for every window:** zero packets on a physical interface except
  - to or from the VPN endpoint (IP:port, proto);
  - DHCP, ARP, ND, RA;
  - with `allowLAN`, link-local and connected-subnet traffic.

| Case | Scenario | Assertion |
|---|---|---|
| LK-01 | Connected baseline (WG UDP; OVPN UDP) | criterion holds for 60 s of `curl`/`dig`/`ping` load |
| LK-02 | `kill -9` the extension while connected (kill switch on) | **Single expected outcome (§10.1.1):** no packet on a physical interface except to the VPN endpoint until the user disconnects or the tunnel reconnects; status leaves `.connected` ≤ 5 s (L-LC-1). If S2 required the on-demand mitigation, packets are allowed only within the measured, documented gap. |
| LK-03 | Reconnect: the server drops (endpoint blackholed by test-router rule), 3 min | blocking continues during `reasserting` (L-KS-1) |
| LK-04 | Sleep/wake (`pmset sleepnow` + `pmset schedule wake`) | no packets before the tunnel is up; reconnects ≤ 30 s (L-RC-5) |
| LK-05 | Wi-Fi → Ethernet → Wi-Fi switch (`networksetup -setnetworkserviceenabled`) | no leak; reasserting → connected ≤ 20 s (L-RC-1) |
| LK-06 | Fragments and large packets: `ping -s 4000` through the tunnel, 1 GB SMB copy, RDP session for 5 min (L-KS-4) | no stalls; throughput ≥ 70 % of baseline |
| LK-07 | OpenVPN over TCP: LK-01..06 repeated with a `proto tcp` profile | same |
| LK-08 | DNS: `scutil --dns` shows the tunnel resolver first with a catch-all; `dig @8.8.8.8 example.com` and `dig @<ISP resolver>`; system resolver lookups | zero UDP/TCP 53 and 853 on the physical NICs; queries observed on utun |
| LK-09 | IPv6: a v4-only full tunnel on a dual-stack LAN, three profiles: kill switch **on** (`wg-ks`), **off** (`wg-v4only-noks`), and off with "Block IPv6 without the kill switch" (`wg-v4only-noks-block6`) | on: no v6 egress on the physical NIC (includeAllNetworks + blackhole); off + toggle: no v6 egress (blackhole); off without toggle: v6 egress to the LAN is **expected** and recorded, matching the Go app and the UI warning (§10.5) |
| LK-10 | Sparkle update N-1 → N with kill switch on (L-KS-3) | the Mac is online during replacement; the tunnel resumes; no leak during "resumed" connect |
| LK-11 | `kill -9` the extension with the kill switch off, then `scutil --dns` (L-DNS-1) | resolver config back to baseline ≤ 5 s |
| LK-12 | Split profile with route protection: a more specific LAN route injected | tunnel routes are still honoured |
| LK-13 | TN3165 matrix (manual, recorded): AirDrop, Continuity/Handoff, Internet Sharing, Xcode device debugging, AirPlay | expected outcome per policy flag documented |
| LK-14 | `cancelTunnelWithError` path: a kill-switch OVPN profile whose server starts rejecting with a fatal error (test server switched to a wrong CA) | the §10.1.1 outcome for E3: blocked until the user disconnects (via `.cancel` or `.holdBlocked`) |
| LK-15 | Captive portal while connected with the kill switch on → "Pause protection 5 min"; repeated with the app `kill -9`'d during the pause | the Mac is online only during the pause; protection resumes at expiry (≤ 60 s late when the app was killed: the §10.4 resume agent) with no leak afterwards; the agent is unregistered after resume. Traffic before the pause is allowed only within the S1-recorded captive exemption (§10.1) |

### 15.4 Fuzzing

libFuzzer targets built **on macOS** with `swiftc -sanitize=fuzzer,address` (Swift) and `clang -fsanitize=fuzzer,address` (the C++ parse entry point), run in CI (10 min) and nightly on the self-hosted Mac (8 h):
- `fuzz_ovpn_tokenizer`
- `fuzz_ovpn_import` (tokenizer → allowlist → normalizer; asserts the normalizer output re-tokenizes to the same stream)
- `fuzz_ovpn3_options` (C++: `OpenVPN3Options` parse of arbitrary bytes, ASan only; memory safety of openvpn3's parser)
- `fuzz_wg_parser`
- `fuzz_crv1_cookie`
- `fuzz_zip_import` (with ZIPFoundation)
- `fuzz_lpwire_decode`

Crashes become regression fixtures in `Tests/Fixtures/fuzz/`.

The Swift-vs-openvpn3 differential is **not fuzzed** in v2.0. The Linux build and the C++ differential harness are cut (§21). Coverage comes from the unit differential over the shared corpus (§15.1), plus the import pipeline's runtime check [6], which rejects any disagreement for real inputs.

### 15.5 Update tests (L-UPD-1)

- A macOS 15 and a macOS 27 VM (Virtualization.framework via UTM, on the dev Mac) or a spare Mac. **Manual, checklist-driven** for v2.0; Tart and MDM-scripted approval are cut (§21).
- Each VM keeps a snapshot "N-1 installed, extension approved by hand, fixtures imported, `rc` channel on". Approval is done by hand once per VM image; later same-team replacements need no re-approval.
- From the snapshot: connect with the kill switch on, then "Check for Updates" picks up the RC from the `rc` channel (§12.1).
- Assert:
  - `systemextensionsctl list` shows N activated and enabled, with N-1 terminated;
  - the tunnel resumes;
  - profiles, credentials (connect without prompt) and history are intact;
  - no dialog other than Sparkle's.
- Also:
  - a downgrade attempt is refused automatically, and "Reinstall tunnel component" performs it on request (§4.6);
  - with the app **quit and the tunnel up**: install N over N-1 by `brew upgrade` and, separately, by Finder drag-replace, then launch → the preflight quiesces, replaces and resumes (§4.2);
  - with a `stayConnected` profile and the auto profile both on-demand enabled: the §12.3 update disables on-demand on both, and both are restored afterwards (N5);
  - **once before GA, a key-rotation drill** on a VM: a test feed item with a DMG enclosure carrying a new `SUPublicEDKey` is accepted, a zip with a new key is refused, and the following zip item signed with the new key is accepted (§1.3 A5, N1).

### 15.6 Security test checklist (each release; Fable reviews the code, these verify behaviour)

- [ ] XPC rejects an unsigned peer, a wrong-identifier peer and an Apple Development-signed copy of the app, before any handler runs; the app rejects a fake extension listener (a team-signed binary registering a lookalike name is impossible without our provisioning; tested in the `FaultInjection` build).
- [ ] Profile ownership: a second macOS user cannot provision or remove another user's profile over XPC.
- [ ] Every forbidden directive is rejected at import **and** at provision, with the app bypassed by a test client.
- [ ] No secret strings in: the unified log (`log show --predicate 'subsystem BEGINSWITH "io.github.steiale.lockplus"' --info --debug` with private data enabled via a configuration profile on the test Mac), the diagnostics bundle, crash reports (forced crash in DEBUG), `defaults read`, NE prefs (`/Library/Preferences/com.apple.networkextension.plist`).
- [ ] Sealed payload files are unreadable without the DP key; deleting the key yields "profiles locked" UI, not a crash.
- [ ] Extension secret files: root:wheel 0600 in a root 0700 directory; unreadable to a non-admin user; the contents are AES-GCM ciphertext (no plaintext key material found by `strings`/`grep` for planted secrets). Admin readability is documented, not tested as a failure.
- [ ] Tampered `profiles/*.json` (policy flipped) → quarantined, and NE preferences unchanged (§3.4). The same for a **replayed** older metadata + `.sealed` pair saved before a policy change (N6).
- [ ] The release build contains no `debugInjectFault`/`LP_FAULT_INJECTION` symbols. The GitHub repository and environment secrets contain no EdDSA key, Developer ID certificate, provisioning profile or notarization credential, and no workflow has a signing or notarization step (N1).
- [ ] Export writes 0600 with `O_NOFOLLOW` (a symlink at the destination is refused); LAContext is required.
- [ ] Zip bomb, 501-entry zip, path-traversal names, huge QR: all rejected within limits.
- [ ] Sparkle: a tampered archive, an unsigned feed and a lower version are each refused.
- [ ] Extension binary links no AppKit, SwiftUI or Sparkle; no `get-task-allow` in release entitlements.
- [ ] A WEB_AUTH server, an encrypted key without a passphrase, and a proxy-auth profile each produce a visible error ≤ 5 s (L-OVPN-4).

---

### 15.7 Test infrastructure (needed from P1 on)

Everything below is built in P1 (part of its estimate) and reused through P5. All server configs are committed under `native/Tools/test-servers/`, and nothing lives in `/tmp`.

| Item | How | Used by |
|---|---|---|
| Linux server VM(s) | 1–2 arm64 Debian VMs in UTM on the dev Mac (bridged), plus a cheap VPS for internet-path tests. Each runs Docker Compose. | everything below |
| WireGuard server | `wg-quick` container; a second peer config with a blackholed first A record (for endpoint failover) | S7, S11, §15.2, LK-* |
| OpenVPN 2.7 server matrix | One `openvpn:2.7` container per profile: (1) UDP AEAD + `tls-crypt-v2`; (2) TCP; (3) CBC-only (`data-ciphers AES-256-CBC`, no NCP fallback, emulating an old server); (4) BF-CBC (`providers legacy default`, `cipher BF-CBC`); (5) `auth-gen-token` on/off variants; (6) PUSH_UPDATE (`push-update-broad` via management); (7) `dns server …` and `dhcp-option` pushes. | S8, S13, §15.2, LK-07 |
| Auth scripting | A ~150-line Python **management-interface client** (`--management-client-auth`) shared by all OpenVPN containers. It answers `>CLIENT:CONNECT` with: accept; `client-deny … "CRV1:R,E:<state>:<b64 user>:Enter code"` then accept the matching response; SCRV1 decode and check (static challenge, both echo variants and the concat format); `client-pending-auth … WEB_AUTH::…` (to test rejection); configurable AUTH_FAILED. It logs every received password and response (test secrets only) so M6 can prove that no stale OTP was re-sent. | S8, §15.2 auth rows |
| Captive-portal AP | A travel router (or a Linux VM with hostapd) whose DNS/HTTP returns 302 to a login page until a button is pressed | §10.4, LK-15 |
| Test router rules | `nftables` on the server VM to blackhole an endpoint (LK-03) and to reset TCP (§10.1.1 E6) | LK-03, S2 |
| macOS test machines | the dev Mac (15 or 26), the self-hosted `macdev` (27), and UTM macOS VMs with manual approval snapshots (§15.5) | S2, S5, S9, S10, §15.5 |
| Real servers | BHP (Sophos) and AllService, manual only; credentials never in CI or files | S8, milestone M5 |

## 16. Key sequences

**Connect (manual):**
1. The user clicks Connect.
2. `ConnectionStore.connect(id)`:
   1. `LegacyAppDetector` gate (§4.5);
   2. if another profile is active, `stopVPNTunnel` and await `.disconnected`;
   3. `manager.isEnabled = true`, `saveToPreferences` (only when it wasn't the enabled config);
   4. `startVPNTunnel(options: nil)`.
3. The extension: `startTunnel` → `TunnelController.start` → validate → `adapter.start` → `networkSettings(plan)` → `host.apply` → data plane up → completion → `.connected`.
4. The app observes `.connected`, starts stats polling, then runs `DNSVerifier` after 3 s.

**Auth prompt (OVPN, OTP profile):**
1. The adapter emits `authRequired`.
2. The controller enters `awaitingAuth(promptID)` and pauses the deadline.
3. `tunnelEvent(authRequired)` reaches the app. `AuthCoordinator` shows the sheet (menu bar shows "Authentication required").
4. The user submits.
5. `answerAuth(promptID, user, base+otp, save:false)` is checked against the current promptID.
6. `provideAuth` → openvpn3 `provide_creds` → `connect()`.
7. CONNECTED → settings → `.connected`.
8. On AUTH_FAILED, a new promptID with `reason: .rejected` is issued and the app replaces the sheet.

**Reconnect (path change):**
1. `PathWatcher.changed` → `setReasserting(true)` → `adapter.reconnect(.pathChanged)`.
2. WG: bump sockets, forced handshake, poll ≤ 15 s. OVPN: `reconnect(0)`.
3. Success → `setReasserting(false)`.
4. Failure → `Backoff.next()` loop; the budget rule depends on the kill switch.

**Update:** §12.3 (Sparkle) and §4.2 preflight (brew, drag-replace).

**Captive portal:** §10.4.

**Uninstall:** §4.4.

**Profile edit while connected:**
1. Save seals revision n+1 and provisions the extension (new revision stored).
2. The connected session keeps running revision n. The UI shows "Reconnect to apply".
3. The next connect loads n+1.

---

## 17. Spike plan (answers NR §6), with go/no-go

Spike duration: **15–20 days** (draft 1's 5 days was not credible for 13 spikes). Each spike has an owner checklist and a written result appended to this document as §17.x "Result". Building the §15.7 test infrastructure is part of P1 and accounts for about 4 of those days.

| ID | NR Q | Question | Method | Go criterion | Fallback / no-go action |
|---|---|---|---|---|---|
| S1 | Q1 | `ssidMatch` without Location on 15/27; `probeURL` behaviour on a captive network; the second probe host; the `includeAllNetworks` captive-network exemption | `.mobileconfig` with VPN on-demand SSID rules; then our app with no Location grant; toggle Wi-Fi networks. Captive-portal AP (§15.7) with the §10.4 rule set; log in; observe whether on-demand re-evaluates. Block the first probe host at the test router → the second rule must connect. With a kill-switch tunnel reasserting on the portal network, record what reaches the portal (CNA, Safari) | On-demand connects and disconnects per SSID on both OSes with no Location prompt. Both probes failing → Ignore rule → CNA shows; one host blocked → still connects. The exempted captive traffic is recorded per OS | SSID: app-assisted mode (§10.4) for all SSID rules. Portal: if `probeURL` is ignored, drop it and rely on "Pause protection" |
| S2 | Q2 | `includeAllNetworks` semantics on **15, 26 and 27** (§10.1.1 E1–E9): `kill -9` of the provider, `stopVPNTunnel`, `cancelTunnelWithError` → does connectivity return or stay blocked; reasserting; OVPN over TCP; a TCP connect from the provider under the flag; the excluded endpoint route; LAN IPv6 with `allowLAN` and the `::/0` blackhole; **saving on-demand rules while connected** (E9, N5). Plus the exclude flags (AirDrop, Xcode device, Sparkle while blocked) and rename-while-connected | BPF capture on `en0` per event, 10 runs each; manual matrix LK-13; save the manager with a changed `localizedDescription` while connected; save it with changed `onDemandRules` and `isOnDemandEnabled` while connected | Each E-row has a recorded result per OS, and §10.1.1 picks the matching design row. AirDrop and Xcode work with `excludeDeviceCommunication`; rename and on-demand saves keep the session | Per §10.1.1 row: `holdBlocked`, the on-demand mitigation, a forced compatibility toggle for OVPN-TCP, documented regressions; defer rename. E9 restarts the session → the E1 keep-alive rule is saved **before** `startVPNTunnel` (and removed after `.disconnected`), and §10.4 rule changes are deferred to disconnect |
| S4 | Q4 | Extension secret store (§6.3): container files from the sandboxed root extension; CryptoKit Secure Enclave wrap (`SecureEnclave.P256.KeyAgreement` + HPKE) from the sysex; optional System keychain | Create, read, rename and delete files; wrap and unwrap the file key; replace the extension; reboot and test **before and after** the first login; on-demand start at boot. Separately, try the System keychain via `SecKeychainOpen` + `kSecUseKeychain` with no temporary-exception entitlement | Files work and survive replacement. SE wrap: works after replacement and after login. Pre-login failure is acceptable (§6.3 decision) | SE wrap fails → plain root file key (§6.3 fallback 2). System keychain fails (expected per forum 672456) → not used |
| S5 | Q5 | XPC via `NEMachServiceName` with a per-version name; replacement edge cases; deactivate → activate of a lower version (§4.6); container persistence after deactivation | App ↔ extension `hello` while the tunnel is down and up; replace the extension while disconnected and (edge case, §4.3) while connected; check `launchctl print` for stale registrations; reinstall N-1 over N | XPC works in both states; the new name is reachable after replacement; no side effects; reinstall works without a reboot (or with one, documented) | Fixed name + mandatory stop-before-replace |
| S6 | Q6 | TN3179 exemption for the root extension | WG endpoint on a LAN IP (192.168.x); no Local Network prompt | Connects with no prompt | Document; the app requests Local Network if needed for diagnostics only |
| S7 | Q7 | WireGuardKit (Go runtime) + openvpn3 (asio/OpenSSL) in one process | One extension; alternate 50 WG/OVPN connects; ASan build; memory over 1 h | No crashes, no symbol clashes (`nm` check for duplicate OpenSSL/BoringSSL symbols), RSS < 50 MB steady | Two system extensions (`…tunnel.wg`, `…tunnel.ovpn`) behind the same `TunnelAdapter`; the app picks the provider bundle ID per profile |
| S8 | Q8 | openvpn3 CRV1 and SC through the shim; **`auth-token` push** and OTP reconnect behaviour (§8.4) | Test server with the management-interface auth script (§15.7); SC with the echo/concat variants; BHP and AllService real profiles. After CONNECTED, record whether `session_token()` is set; force `ping-restart` and check the server/auth log for a re-sent OTP, with and without the purge. After the purge, confirm the `NEED_CREDS` event, that the re-prompt answer (username re-supplied + fresh `connect()`) connects, and what a TLS renegotiation does. Repeat with `auth-nocache` injected instead of the patch | All four flows work; the username from the CRV1 cookie is used; whether BHP/AllService push `auth-token` (and their `reneg-sec`) is recorded; with the purge, no stale OTP reaches the server and the re-prompt reconnects. If `auth-nocache` gives the same log, the patch is dropped | Auth flows: **no-go for OpenVPN-in-NE** if CRV1 or SC cannot work (ship WG-only native, keep the Go app as the OpenVPN line, re-evaluate). Stale OTP still sent → disable engine-internal reconnect for OTP profiles without a token (§8.4) |
| S9 | Q9 | Xcode 27 Developer ID export end to end | `-exportArchive`, notarize, install in a clean VM, activate, connect | Extension loads (no "Plugin failed") | Inside-out re-sign script |
| S10 | Q10 | Sparkle update replacing the extension while connected and with the kill switch on; brew/drag-replace with the app closed (§4.2 preflight) | `rc` channel in the VM, §12.3 flow; then `brew upgrade` and a Finder drag-replace with the app quit and the tunnel up | Tunnel resumes; the Mac is never offline > 15 s; no XPC breakage | Require disconnect before "Install and relaunch" with an explicit dialog |
| S11 | — | openvpn3 (built with `USE_TUN_BUILDER`) on the NE utun fd (§7.3); **`dup` ownership and `tunPersist`** (N2) | Return `dup()` of the scanned fd from `tun_builder_establish`; check the AF-header handling (`tun_prefix`). Force 20 reconnects, an AUTH_FAILED and a `holdBlocked` teardown: verify with `lsof` that NE's original fd stays open and no dup leaks. Repeat with `tunPersist = true`: reconnects to the same and to a different server (settings re-applied, `tunnelRemoteAddress` updated) | Traffic flows; throughput ≥ 300 Mbit/s on M1; NE's fd survives every teardown; fd count stable. `tunPersist` decided (kept off unless it measurably shortens `reasserting` without stale settings) | socketpair bridge. `tunPersist = true` misbehaves → stays off |
| S12 | — | `fetchLastDisconnectError` passes custom domain/code/userInfo | Cancel with a custom NSError; read it in the app | Domain and code are intact | `tunnelSnapshot.lastError` |
| S13 | — | openvpn3: tls-crypt-v2, CBC-only server, BF-CBC with `enableLegacyAlgorithms`, PUSH_UPDATE, `dns` options, `pull-filter`; **[7b] `ClientOptions` construction without connecting** (§8.1); the first run of the `EngineSupport` generator (§8.2) over the Go allowlist and the real-profile corpus | Test servers (§15.7); host-side test binary for [7b] and the generator | All connect; DNS options arrive via `tun_builder_set_dns_options`; pull-filter honoured; [7b] performs no I/O and throws `UNUSED_OPTIONS` for each fatal class; the BHP/AllService profiles pass [7b] after normalization | Per item: mark unsupported at import with a clear message (PUSH_UPDATE: reconnect to apply). [7b] not side-effect free → the vendored `handle_unused_options` variant (§8.1) |

S3 (DoH/DoT in tunnel settings) is cut with the feature (§21).

**Overall spike gate (NR §3 "Spike gate"):** BHP and AllService connect, CRV1 and SC work, a CBC-only server works, and tls-crypt-v2 works. Failing S8 or S13 (tls-crypt-v2/CBC) means OpenVPN-in-NE is no-go as above. Failing S7 means the two-extension fallback, about 3 more days. S2 has no no-go outcome, but its result selects the §10.1.1 design row and must be recorded before P2b starts on the kill switch.

---

## 18. Phased implementation plan

Estimates are in developer-days. Every phase's Definition of Done includes:
- all unit tests green;
- review by lens: Sonnet first pass, Opus architecture, and a **Fable security pass on extension, keychain, parser and XPC code**;
- **every finding fixed**;
- this document updated where reality differed.

| Phase | Scope | Milestone / Definition of Done |
|---|---|---|
| **P1 Spike** (15–20) | §15.7 test infrastructure (≈ 4 d), then §17 (S1, S2, S4–S13). Throwaway code in `native/spike/`. Rough split: S8 + S13 + S11 (openvpn3 build with `USE_TUN_BUILDER`, shim, auth, [7b], generator) ≈ 6–8 d; S2 on three OS versions ≈ 2–3 d; S4, S5, S10 ≈ 2 d; S1, S6, S7, S9, S12 ≈ 2–3 d. | M1: every spike has a written result and decision; the §10.1.1 row chosen; the OpenVPN go/no-go recorded; this document amended. |
| **P2a Skeleton** (6) | Xcode project, xcconfigs, version-check, entitlements, Developer ID signing for dev builds on the dev Mac only (N1), `SystemExtensionManager` (§4) with every outcome, **the §4.2 preflight and §4.6 reinstall**, XPC skeleton with peer validation and timeouts (§5), CI lint/unit/build-dev (ad-hoc signed, no secrets), debug menu. | M2: a fresh VM installs a notarized dev build, approves, `hello` round-trips; a wrong-signature or Apple Development-signed client is rejected; the extension `otool -L` check passes. |
| **P2b WireGuard engine** (8) | WG parser/validator port, fork patches 1–5, `TunnelController` state machine with fakes (including `blockMode`), `WireGuardAdapterImpl`, `NetworkSettingsBuilder` (incl. the §10.5 IPv6 blackhole tied to the kill switch, plus its per-profile toggle), path, sleep, watchdog, backoff, stats/sessions. | M3: WG connects with data-plane-up semantics; LK-01..05, LK-08, LK-09, LK-11 pass for WG; the state-machine suite is complete. |
| **P2c Storage, credentials, updates** (10) | `ProfileStore` (sealed payloads, metadata HMAC, the §6.8 locked-profiles UX), `CredentialStore` (DP), `ContainerSecretStore` (§6.3, with the S4 key-wrap choice), provision/reconcile, kill-switch policy (§10.1 incl. the S2-selected row), DNS (§10.2), `DNSVerifier`, Go migrator (WG part), minimal UI (list, connect, import file, pause protection with the §10.4 resume agent), **Sparkle (§12.1) with the dev-Mac `release.sh` (build, sign, notarize, EdDSA from a fresh tagged clone; N1) and `rc` channel, and the §12.3 update flow**, DMG, CI without signing material (optional `repro` job), `lockplus-native` cask. | **M4: WireGuard beta.** Alex's Flo VPN runs a week on the beta; the leak harness passes for WG; the N-1 → N **Sparkle** update test passes (beta1 → beta2), and so do the brew and drag-replace variants (§15.5). |
| **P3 OpenVPN** (20–30) | Tokenizer/allowlist port with shared fixtures, normalizer with caps, `OpenVPN3Options` differential, the `EngineSupport` generator and CI diff, the OpenSSL static build, `OpenVPN3Shim` (client with `USE_TUN_BUILDER`, [7b] validation, TunBuilder with endpoint exclusion and the `dup` fd hand-off (§7.3), events, logs, redactor, the one-call `purge_user_pass` patch or `auth-nocache` per S8, `NEED_CREDS` → re-prompt → fresh `connect()`), `OpenVPNAdapterImpl`, auth UI (§8.4), import report UX, legacy crypto, DNS mapping, OVPN migration with legacy keychain, macOS fuzzers. | **M5: OpenVPN beta.** BHP and AllService connect (password, SC, CRV1, re-prompt, OTP reconnect without lockout); the full leak harness passes including LK-07 and LK-14; the 8 h fuzz run is clean; the Fable review of shim and parser is fully fixed. |
| **P4 UI parity** (13–22) | MenuBarController (§11.3), detail, editor with highlighting, statistics, history, logs, diagnostics, auto-connect (incl. captive-portal re-probe and the two probe hosts), settings, onboarding, String Catalogs ×4, accessibility audit, `SMAppService.mainApp`, in-app Uninstall, diagnostics bundle. (Sparkle moved to P2c.) | **M6: release candidate.** Parity checklist (§11.5) complete; VoiceOver pass; de/ko/ja reviewed; the security checklist (§15.6) passes; the update test passes on 15 and 27; the §15.5 key-rotation drill (DMG enclosure) passes. |
| **P5 Cutover** (5–10) | Go v1.2.0 Farewell (§13.3), cask transition (§13.4), zap audits, README and screenshots. | **M7: GA.** Native 2.0.0 is in the `lockplus` cask; Go helper removal verified on Alex's two Macs (pf anchors gone, DNS restored, `launchctl print` clean); no data loss in the migration report. |

Total: 77–106 days. That is above NR's original 65–95 (NR §5 now quotes this total), by the realistic spike estimate, the moved Sparkle work and the review's additions, partly offset by the §21 cuts.

---

## 19. Traceability: L-* requirements → design → test

| Requirement | Satisfied by (section) | Test |
|---|---|---|
| L-LC-1 no zombie tunnels | §7.2 (`fatal` → `cancelTunnelWithError`, or `holdBlocked` with status `.reasserting`), §11.2 (status only from NEVPNStatus + `fetchLastDisconnectError`) | §15.1 state machine "fatal → cancel/hold"; §15.2 fault injection ≤ 5 s (non-gating build); LK-02 (gating, shipped RC) |
| L-LC-2 connected = data plane up | §7.2 completion rule, §9.3 handshake, §8.4/§7.3 OVPN CONNECTED + settings | §15.1 completion-once/order tests; §15.2 WG/OVPN connect timing |
| L-LC-3 timeouts on every cross-process call | §5.4 per-method timeouts, liveness rule; §5.1 connect is not XPC | §15.1 XPC wire timeout tests; §15.2 slow-connect test (server delays 60 s; no "dead" UI) |
| L-LC-4 one source of truth | §10.1 policy in the NE config; §11.2 stores | §15.1 store tests; LK-03 with connects from the menu bar, window and on-demand |
| L-RC-1 path changes | §7.4 PathWatcher → reasserting | LK-05 |
| L-RC-2 dead peer | §7.5 watchdog, OVPN keepalive floors | §15.1 watchdog tests; LK-03 |
| L-RC-3 backoff | §7.6 `Backoff`, server pause honoured, no auth auto-retry | §15.1 backoff tests; lint rule |
| L-RC-4 auth during reconnect | §7.2 deadline pause, §8.4 promptID, §8.4 OTP credential purge without `auth-token` (`NEED_CREDS` → re-prompt with username → fresh `connect()`) | §15.1 auth-pause and stale-answer tests; §15.2 OTP reconnect with and without `auth-gen-token`; S8 |
| L-RC-5 sleep/wake | §7.4 | §15.1; LK-04 |
| L-KS-1 verify behaviour | §15.3 harness against the shipped RC as a release gate (§12.4); §10.1.1 S2-derived semantics and Go-parity design | LK-01..15; S2 |
| L-KS-2 never toggle while connected | §10.1 `updatePolicy` throws `.mustBeDisconnected`; UI disables | §15.1 ProfileStore test; UI test |
| L-KS-3 updates while blocked | §12.3 quiesce (on-demand off on every manager) → replace → resume (Sparkle); §4.2 preflight quiesce before any activation request (brew, drag-replace); §10.4 pause for captive portals, ended by the resume agent even after a crash | LK-10, LK-15; §15.5; S2 E9; S10 |
| L-KS-4 fragments and TCP | §9.3 MTU/MSS floors; harness cases | LK-06, LK-07 |
| L-DNS-1 crash leaves no state | §10.2 (NE-owned DNS) | LK-11 |
| L-DNS-2 every pushed form | §8.5 mapping table, openvpn3 pull-filter | §15.1 DNS table tests; §15.2 push server; S13 |
| L-DNS-3 diagnostics fail closed | §10.2 `DNSVerifier` (`.unknown` ≠ safe) | §15.1 verifier tests with unreadable/mismatch fixtures |
| L-MTU-1 MTU, endpoints, floors | §9.3, §8.1 floors | §15.2 MTU applied, endpoint failover; LK-06 |
| L-OVPN-1 allowlist + identical parser | §8.1 pipeline (port + canonical + openvpn3 differential + [7b] `ClientOptions` check, caps 256 KiB/512 B), §8.2 generated `EngineSupport` | §15.1 shared fixtures, differential, generated-table diff; §15.2 fatal-class import rejections; §15.4 fuzzing; S13 |
| L-OVPN-2 2.7 traps | §8.6 legacy crypto, §8.7 no verb logging, OpenSSL legacy provider | §15.2 CBC-only and BF-CBC servers; log grep; S13 |
| L-OVPN-3 auth flows | §8.4 | §15.2 password/SC/CRV1/AUTH_FAILED/WEB_AUTH; S8 |
| L-OVPN-4 errors reach the user | §5.5 codes, §11.7 | §15.6 last item; S12 |
| L-CRED-1 keychain location | §6 (DP app store; root-owned sealed container store for the extension, §6.3; raw `Data`, UUID keys, no `passwordReference`; app → XPC → extension hand-off) | §15.2 secret-store tests; S4; §15.6 |
| L-MB-1 menu bar | §11.3 | §15.1 RateMeter; UI tests (menu rebuilt on open, item removed on quit, visibility banner) |
| L-EXT-1 one dialog, no loops | §4.2 table | §15.2 activation outcomes |
| L-EXT-2 activate every launch, bump both keys | §4.2, §2.6 | version-check CI; §15.5 |
| L-EXT-3 replacement while connected | §4.3 per-version Mach name; §4.2 preflight stops the tunnel before submitting; the replacement delegate is a pure compare | S5, S10; §15.1 preflight table; §15.5 |
| L-EXT-4 uninstall | §4.4 (incl. `wipeAllSecrets` of the container store; cask `must_succeed: false`) | §15.2: after uninstall, `systemextensionsctl list` is empty, and no keychain items, container secret files or managers remain |
| L-EXT-5 no AppKit in extension | §2.2 dependency rules | CI `otool -L` check |
| L-EXT-6 Developer ID dev builds, debug loop | §2.4, §2.7, §4.2 debug menu, §14.1 first light | M2 |
| L-UPD-1 updater | §12.1 (EdDSA key off CI, release built and signed only on the dev Mac, DMG enclosure for key rotation, `rc` channel), §12.3, §4.2 downgrade refusal, §4.6 user-initiated reinstall | §15.5; §15.6 Sparkle items |
| L-DIST-1 cask hygiene | §12.2 zip name, zap audit, absolute paths, `auto_updates` | CI zip-name assert; tap grep job |
| L-DIST-2 notarization and export | §12.4 (dev-Mac `release.sh`; CI holds no signing material) | S9; `release.sh` run on every release; §15.6 CI-secrets check |
| L-MIG-1 copy-only migration + Go uninstaller | §13 | §15.2 migration fixtures (a Go data dir snapshot) with a checksum showing the source is untouched; M7 verification |

NR §3 "Security posture to keep":
- import caps (§3.5);
- names validated (§3.1);
- exports 0600 `O_NOFOLLOW` (§15.6);
- XPC peer validation (§5.3);
- no web views (§11.4);
- mandatory reviews (§18).

NR §4 pitfalls 1–15 map to §12.4, §2.4, §2.2, §6, §4.3, §2.6, §4.4, §10.1, §12.3, §7.2, §7.4, §10.2, §10.4, §11.1/§13.1 and §9.2, respectively.

Design-review findings (draft 2) → design → test:

| Finding | Design | Test |
|---|---|---|
| C1 extension secret store | §6.3, §3.3, §1.3 A2 | S4; §15.2 secret store; §15.6 secret files |
| H1 `includeAllNetworks` semantics | §10.1.1, §7.2 `blockMode` | S2; LK-02, LK-07, LK-14 |
| H2 synchronous replacement delegate | §4.2 preflight, §4.3, §12.3 | §15.1 preflight table; S10; §15.5 brew/drag variants |
| H3 openvpn3 option handling | §8.1 [7b] + caps + build rules, §8.2 generator, §8.4 `ProvideCreds`, §8.5 endpoint exclusion | §15.1 generated-table diff and caps; §15.2 fatal classes; CI `engine-support`; S13 |
| M1 Sparkle trust anchor | §12.1, §1.3 A5 | §15.6 (no EdDSA key in CI) |
| M2 rollback | §4.6 | §15.5; S5 |
| M3 harness tests the shipped binary | §15.3, §15.2 `FaultInjection` | §15.6 symbol check |
| M4 captive portals | §10.4, §11.3 | S1; §15.2 portal; LK-15 |
| M5 IPv6 for v4-only full tunnels (revised by N4) | §10.5 | LK-09 (three variants) |
| M6 OTP lockout on reconnect | §8.4 | S8; §15.2 OTP reconnect |
| M7 sequencing and infrastructure | §18, §15.7 | M1, M4 milestones |
| M8 reveal gate limit | §1.3 A6 | §15.1 RevealGate |
| LOW items | §5.3, §1.3 A1/§3.4, §6.8, §4.5/§13.3, §4.4, §21 | §15.6; §15.1 HMAC; §15.2 |

Re-review findings (draft 3) → design → test:

| Finding | Design | Test |
|---|---|---|
| N1 release built and signed on the dev Mac; DMG for key rotation | §1.3 A5, §1.4 (7), §2.7, §12.1, §12.2, §12.4 | §15.6 CI-secrets check; §15.5 key-rotation drill; optional `repro` hash compare |
| N2 `dup` of the utun fd; `tunPersist` | §7.3, §7.2 `holdBlocked` | S11; §15.1 shim fd ownership |
| N3 pause survives a crashed app | §10.4 resume agent, §11.3, §4.4 | §15.1 resume agent; §15.2 portal; LK-15 |
| N4 IPv6 blackhole follows the kill switch | §3.1, §10.5 | LK-09 (three variants); §15.1 NetworkSettingsBuilder IPv6; S2 E8 |
| N5 on-demand off on every manager before replacement | §4.2, §12.3 | §15.5; S2 E9 |
| N6 metadata replay | §3.1, §3.3, §3.4 | §15.1 HMAC (replay case); §15.6 |
| N7 probe host dependency | §10.4 | S1; §15.2 portal with the first probe host blackholed |
| N8 / M6 minimal patch, `NEED_CREDS` semantics | §8.4 | S8; §15.2 OTP reconnect |
| H3 nit `remote_bypass` | §8.5 | — (source fact) |
| H1 extra captive exemption | §10.1, §10.4 | S1; LK-15 |
| Drifts (NR §5 days, Mach name, §6.8 rule) | §6.8, NR §2, NR §5 | §15.1 HMAC/locked |

---

## 20. Open risks

1. **OpenVPN-in-NE viability (S8/S13).** If openvpn3 can't do CRV1/SC, or the corporate servers need features openvpn3 lacks, the OpenVPN line stays on Go for longer.
2. **Extension secret store (S4).** Root ownership is the only guaranteed boundary; the Secure Enclave wrap from a sysex works per DTS but is not officially supported (forum 804612), and it fails before the first login after boot. Admins are out of scope. If a future macOS changes SE access for daemons, the store falls back to the plain root file key, with no data loss, because reconcile re-provisions from the app.
3. **Per-version Mach names and launchd (S5).** Unknown accumulation behaviour across many dev builds. The mitigation is a periodic deactivate/activate in dev.
4. **On-demand + interactive auth.** OTP profiles can't auto-connect. Users who expect this get a clear UI restriction, not a feature.
5. **SSID rules without Location (S1).** If they need Location, auto-connect depends on the app running for SSID-specific behaviour.
6. **`includeAllNetworks` semantics (S2, §10.1.1).** Behaviour on provider death and on `cancelTunnelWithError` is unknown until S2. If provider death fails open, the native kill switch is weaker than the Go one by the measured restart gap, and this is documented to users. Expect user reports about AirDrop, Continuity and Sidecar; the compatibility toggle exists for this.
7. **Fork maintenance.** WireGuardKit and openvpn3/OpenSSL are three upstreams we must track, plus one minimal openvpn3 patch exposing `purge_user_pass()` (§8.4), which S8 may replace with the native `auth-nocache`. The monthly watch job, the `EngineSupport` regeneration diff and pinned toolchains mitigate this, but the bus factor is 1.
8. **Memory hygiene limits.** XPC, SwiftUI and openvpn3 make copies we can't zero. This is accepted and documented, not solved.
9. **The dev Mac as the only release machine (M1, N1).** The EdDSA key, the Developer ID identity and the notarization credentials live only there, and the release is built there. That makes the dev Mac the single point of compromise and makes releases depend on that machine being available. The 1Password backup of the EdDSA key is the recovery path; a lost Developer ID identity is re-issued by Apple, and a lost or stolen EdDSA key is rotated with a DMG enclosure (§1.3 A5). A dev-Mac compromise is already game over for signing identities; CI no longer adds a second path.
10. **Unprotected windows by design.** The §4.2 quiesce (updates by brew or drag-replace), "Pause protection" (§10.4), and the captive-portal Ignore rule all leave the Mac online without the tunnel for a bounded, user-visible time. A pause no longer outlives a crashed app: the resume agent ends it within 60 s of expiry (§10.4), unless the user has disallowed LockPlus's background item, in which case it ends at the next launch. On-demand auto-connect also fails open if both probe hosts are unreachable (§10.4).
11. **IPv6 for v4-only full tunnels (§10.5).** With the kill switch on (or the per-profile toggle), the blackhole causes Happy Eyeballs delays, connect timeouts for clients without Happy Eyeballs, and unreachable IPv6-only and LAN-IPv6 services. With the kill switch off and no toggle, IPv6 bypasses the tunnel, as in the Go app; the UI warns.
12. **Device-bound profiles (§6.8).** A Time Machine restore to a new Mac loses every profile that wasn't exported. Users who ignore the export nudge will be surprised.

---

## 21. Later (cut from v2.0)

Cut to fit one developer's capacity. None of these items is a security control the v2.0 design depends on.

| Item | Was in draft 1 | Why cut / what replaces it |
|---|---|---|
| Linux fuzz build and the C++ differential fuzz harness | §2.2, §15.4, §12.4 | macOS `-sanitize=fuzzer` covers memory safety of every parser. The differential is covered by unit fixtures and the runtime check [6] |
| Tart VMs with MDM-scripted extension approval | §12.4, §15.5 | Manual update test on UTM snapshots or a spare Mac (§15.5) |
| DoH/DoT in tunnel settings (spike S3) | §10.3, §8.5 | Plain DNS inside the tunnel |
| `ssidProfileMap` (SSID → specific profile) | §3.2, §10.4, §13.1 | One auto profile; the Go map is reported, not migrated |
| ICMP latency from the root extension | §11.5 | WG handshake RTT; OVPN TCP connect when disconnected |
| Per-connection XPC token bucket | §5.4 | Size caps and deadlines; peers are team-pinned |
| Launch/environment constraints | §1.3 A1 (claimed, never configured) | Hardened runtime + team-scoped keychain access |
| OS-enforced reveal/export gate (HPKE copy sealed to an SE key with `.userPresence`) | — (review M8) | The app-enforced `RevealGate` with its stated limit (§1.3 A6) |
| Passphrase-encrypted export-all | — (review LOW) | Plain export-all with a warning and the §6.8 nudge |
| System keychain as the extension store | §6.3 | Container files; may return if S4 shows a supported path |
