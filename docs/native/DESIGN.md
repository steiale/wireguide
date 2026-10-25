# LockPlus Native: technical design

Status: draft 1, 2026-10-25. Implements the decision in [`../NATIVE-REWRITE.md`](../NATIVE-REWRITE.md) (cited below as **NR**). Every `L-*` requirement in NR §3 is addressed by name; §19 maps each one to the section that satisfies it and to its test.

This document is written for one developer working with AI coding agents. Every section ends in something implementable: a type, a sequence, a rule, or a test. Where Apple behaviour is uncertain, the text states the **assumption**, the **spike** that validates it (§17), and the **fallback**.

Conventions:
- `MUST`/`MUST NOT` are hard rules. Reviewers reject code that breaks them.
- **Decision** marks a choice this document makes that NR leaves open.
- Team ID: `M53GHX9FAY`. App bundle ID: `io.github.steiale.lockplus.mac`. Extension: `io.github.steiale.lockplus.mac.tunnel`.

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
                                    │  System keychain items (root, ACL = this ext)    │
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
| B3 | User ↔ app (files, QR, zip, clipboard) | untrusted profiles | Every parser treats its input as hostile, with caps (§3.6, §8.1, §9.1). |
| B4 | Extension ↔ VPN server | handshake, pushed options, packets | A server can be malicious or MITM'd. Pushed options are allowlisted (§8.5). |
| B5 | App ↔ update channel | appcast, archives | EdDSA, Developer ID team match, signed feed, no downgrades (§12). |
| B6 | Extension ↔ System keychain | secrets at rest | Item ACLs trust only the extension's designated requirement (§6). |
| B7 | App ↔ legacy Go app | tunnel files, legacy keychain, helper socket | Read-only and copy-only. Legacy data is validated like any import (§13). |

### 1.3 Threat model (STRIDE per adversary)

**A1. Local malware running as the same user (no root, no TCC grants).**
- *Spoofing:* it connects to our Mach service and pretends to be the app.
  - Mitigation: the listener sets `setConnectionCodeSigningRequirement` (§5.3), so an unsigned or foreign-team peer is rejected before any message.
- *Tampering:* it modifies `/Applications/LockPlus.app`, which a drag-install leaves user-writable.
  - Mitigation: a modified bundle fails dynamic code validation, so the extension refuses it, and the hardened runtime blocks DYLD injection.
  - Gatekeeper and launch constraints re-check on the next launch.
- *Tampering:* it rewrites `profiles/*.json` metadata.
  - Mitigation: metadata carries no security policy the extension trusts blindly. The extension takes policy from NE preferences, which the user cannot write, and from its own provisioned copy.
- *Information disclosure:* it reads App Support.
  - Mitigation: payloads are AES-GCM-sealed with a key in the data-protection keychain (§3.4). Same-user code without our team signature cannot read that key.
  - Credentials live only in the keychains.
  - **This is an improvement over the Go app, which kept plaintext 0600 files.**
- *Information disclosure:* it reads unified logs.
  - Mitigation: secrets never reach `Logger` (§14). Dynamic strings are `.private`.
- *Denial of service:* it runs `scutil --nc stop`, kills the app, or floods XPC.
  - Accepted, because same-user code can always disrupt.
  - Kill-switch profiles fail closed: includeAllNetworks keeps traffic blocked while reasserting (§10.1).
  - The XPC listener rate-limits each connection (§5.4).
- *Elevation of privilege:* it uses the root extension as a confused deputy (file read/write, exec).
  - Mitigation: the extension is sandboxed and exposes no path-taking or exec-taking API.
  - Profiles go through an allowlist with no path directives (§8.1), and openvpn3 has no script hooks.

**A2. Other local users.**
- NE configurations are system-wide, so another user can see the profile names in System Settings and start them.
- *Disclosure:* they cannot read the payload or credentials. App Support is 0700, the data-protection keychain is per-user, and System keychain items are ACL'd to the extension.
- *Tampering:* another user's copy of LockPlus can see our managers through `loadAllFromPreferences`.
  - Mitigation: `providerConfiguration.ownerUID`. The app hides and refuses to edit foreign profiles.
  - The extension enforces ownership on every profile-scoped XPC call using the peer's `effectiveUserIdentifier` (§5.4).
- *Residual risk:* another user can toggle a tunnel from System Settings. This is documented and inherent to macOS.

**A3. Malicious profiles (.ovpn/.conf/zip/QR from an attacker).**
- Root file read/write, library loading and exec through directives.
  - Mitigation: an allowlist, the openvpn-exact tokenizer, and a canonical re-serialization verified by openvpn3's own parser (§8.1).
  - The extension re-validates the profile and runs sandboxed.
- Parser memory-safety bugs in openvpn3's C++.
  - Mitigation: libFuzzer + ASan on the shim's parse entry point (§15.4).
  - The extension parses only canonical text it generated itself after validation.
- Zip bombs and zip-slip.
  - Mitigation: 500 entries max, 10 MiB per entry decompressed, 1 MiB per profile, and nothing is unpacked to disk.
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
  - Sparkle's Developer ID team-match check.
  - HTTPS only.
- Attack: a downgrade to a vulnerable build.
  - Mitigation: Sparkle never offers a lower version.
  - The extension's `actionForReplacingExtension` returns `.cancel` when the incoming version is lower (§4.3).
- Attack: a stolen EdDSA key.
  - Mitigation: Developer ID notarization is still required.
  - The key lives only in a GitHub Actions environment secret with required reviewers, plus an offline backup.

**A6. Physical access to an unlocked Mac.**
- Exporting or viewing secrets.
  - Mitigation: Reveal, Edit-config, Export and Export-all require `LAContext` `.deviceOwnerAuthentication`, with a 60 s reuse window.
- Disconnecting the VPN or disabling the kill switch.
  - Possible by design for the user. Changing the kill switch requires the tunnel to be disconnected (L-KS-2), so it is visible.
- Reading the System keychain.
  - Requires an admin password. Items are created non-extractable to non-trusted apps.

### 1.4 Security invariants (checked in review and in tests)

1. No secret in `providerConfiguration`, `UserDefaults`, plaintext files, logs, crash reports, XPC error strings or `NSError.userInfo`.
2. The extension never trusts the app's validation. Every payload is re-validated at provision **and** at connect.
3. Every XPC call has a timeout. No call waits for a tunnel connect.
4. The kill-switch policy lives only in the NE configuration (L-LC-4).
5. The extension links no AppKit, SwiftUI or Sparkle (L-EXT-5). CI greps `otool -L`.

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
    LockPlusCore/           # Foundation-only; builds on Linux for fuzzing
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
| `LockPlusCore` | SPM library, modules `LPModel`, `LPParsing`, `LPWire` | Foundation | AppKit, SwiftUI, NetworkExtension, Security, CryptoKit (so the parsers build on Linux for fuzzing) |
| `TunnelEngine` | SPM library | LockPlusCore, NetworkExtension, Network, Security, os | AppKit, SwiftUI, Sparkle |
| `WireGuardBridge` | SPM library + `WireGuardGoBridge` External Build System target (`make` → `libwg-go.a`, arm64, current wireguard-go) | — | AppKit |
| `OpenVPN3Shim` | SPM library, ObjC++ (`.mm`), modules `OpenVPN3Shim` (client) and `OpenVPN3Options` (options parser only, no crypto or network) | openvpn3 headers, OpenSSL static (client module only) | AppKit |
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
- `NSLocationWhenInUseUsageDescription`, used only by the optional SSID→profile map (§10.4)
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

- Two Developer ID provisioning profiles, one per bundle ID, each with the NE capability, app groups, and (app only) keychain sharing and system-extension install. They are stored in the CI keychain and on the dev Mac.
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
    public var ssidProfileMap: [String: UUID] = [:] // optional, app-assisted (§10.4)
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
| Profile metadata | `~/Library/Application Support/io.github.steiale.lockplus.mac/profiles/<uuid>.json` (0600, dir 0700) | JSON `Profile` | no |
| Profile payload, app copy (canonical `.conf` / canonical `.ovpn` text) | `…/profiles/<uuid>.sealed` (0600) | `AES.GCM.SealedBox.combined`, AAD = `uuid‖revision` | **yes**, sealed |
| Payload sealing key | data-protection keychain, service `io.github.steiale.lockplus.mac.payload-key`, account `v1` | 32 random bytes | yes |
| OVPN credentials, app copy | DP keychain, service `io.github.steiale.lockplus.mac.credentials`, account `<uuid>` | `CredentialRecord` binary plist | yes |
| Settings, auto-connect, history, migration marker | `…/settings.json`, `history.json`, `migration.json` (0600) | JSON | no |
| NE configuration | NE preferences, one `NETunnelProviderManager` per profile | see below | **no** |
| Payload, extension copy | System keychain, service `io.github.steiale.lockplus.mac.tunnel.payload`, account `<uuid>` | canonical text bytes | yes |
| Credentials, extension copy | System keychain, service `io.github.steiale.lockplus.mac.tunnel.credentials`, account `<uuid>` | `CredentialRecord` | yes |
| Extension runtime state (session ring, auth backoff, provision index) | extension sandbox container `Data/Library/Application Support/state.plist` (root, 0600) | plist | no |

- The app data directory is named after the **bundle ID**, never `lockplus`.
  - So no Go-app cask `zap` stanza can ever match it (L-DIST-1, the bb50f10 incident).
- `providerConfiguration` (≤ 2 KiB, enforced):
  ```swift
  ["v": 1, "profileID": "<uuid>", "kind": "wg"|"ovpn", "revision": 7, "ownerUID": 501,
   "dnsMode": "tunnelOnly", "mtu": 1420?, "auth": ["interactive": true]]
  ```
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
- The store keeps a **single cached `[UUID: NETunnelProviderManager]`**. `loadAllFromPreferences` is called once at launch and again after a `NEVPNConfigurationChange` notification; managers are never reloaded per call (NR §4 practices).

### 3.5 Import caps (ported, NR §3 "Security posture")

| Input | Cap |
|---|---|
| single profile file | 1 MiB (`.ovpn`, matches `maxOVPNSize`), 64 KiB (`.conf`) |
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
    func activate()                             // idempotent; called on every launch (L-EXT-2)
    func deactivate() async throws              // uninstall path (L-EXT-4)
    var machServiceName: String { get }         // read from embedded ext Info.plist
}
```

### 4.2 Activation on every launch (L-EXT-1, L-EXT-2)

1. At `applicationDidFinishLaunching`, run `activate()` once.
   - First call `propertiesRequest(forExtensionWithIdentifier:)` to learn whether the extension is `isAwaitingUserApproval`. If it is, show the approval **banner** rather than a new modal.
2. Submit `OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier:queue: .main)`.
3. Handle the delegate callbacks:

| Callback / result | Action |
|---|---|
| `actionForReplacingExtension(existing, ext)` | Compare `(CFBundleShortVersionString, CFBundleVersion)` numerically. If the new one is higher, first run `UpdateCoordinator.quiesceTunnel()` (§12.3), then return `.replace`. If equal, `.replace` (dev rebuilds with the same stamp are harmless). If **lower**, `.cancel` and `state = .failed(.downgradeRefused)`, unless a DEBUG build has `LPAllowExtensionDowngrade` set. |
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
- Debug menu (DEBUG builds and `⌥`-click on About):
  - Activate;
  - Deactivate;
  - "Deactivate + Activate" (L-EXT-6);
  - "Show extension log".

### 4.3 Replacement policy

- The system replaces the extension when the app requests activation of a bundle whose versions differ. We always answer `.replace` (except downgrades), **but only after the tunnel is quiesced** (L-EXT-3, L-KS-3).
- `NEMachServiceName` includes `CURRENT_PROJECT_VERSION`, so the old extension's listener and the new app never talk across versions (FB17032197). The app connects to the name in **its own** embedded extension's plist. Before replacement completes, that lookup fails, and the app shows "Updating tunnel component…".
- **Assumption A-EXT-1:** a per-version Mach name has no side effects beyond a launchd registration per version. Spike S5 validates this. **Fallback:** a fixed name plus the mandatory stop-before-replace rule, which already prevents the FB17032197 scenario.

### 4.4 Uninstall (L-EXT-4)

The Settings › Advanced › "Uninstall LockPlus…" sequence:
1. Authenticate with `LAContext`, then confirm.
2. For every manager: `isOnDemandEnabled = false`, save, `stopVPNTunnel()`, wait for `.disconnected` (10 s timeout).
3. XPC `wipeAllSecrets(ownerUID)`, which makes the extension delete its System keychain items and state for this UID. Errors are recorded but not fatal.
4. `removeFromPreferences()` for each owned manager.
5. Delete the DP keychain items (payload key, credentials).
6. `deactivationRequest`. This may require admin approval or a reboot; both are shown.
7. Ask "Also delete your profiles and history?" before removing App Support (default **No**).
8. `SMAppService.mainApp.unregister()` if registered.
9. Move the app to the Trash with `NSWorkspace.recycle`, then quit.

The cask's `uninstall` runs the app headless with `--uninstall-system-components` (steps 2–6, no UI, 60 s timeout), followed by `quit`.

### 4.5 Coexistence with the Go app

Detection (`LegacyAppDetector`, app side; the extension cannot see pf):
1. `/Library/LaunchDaemons/io.github.steiale.lockplus.helper.plist` exists → helper installed.
2. Connect to `/var/run/lockplus/lockplus.sock` (0600, owned by this user, per `internal/ipc/transport_unix.go`) with a 2 s timeout and send the Go IPC status request.
   - The response tells us whether a tunnel is active or the kill switch is enabled. We send a read-only call only.
3. `NSRunningApplication` with bundle ID `io.github.steiale.lockplus` → the Go GUI is running.
4. `/Library/Application Support/lockplus/dns-journal.json` or `pf-was-enabled` exists → state is left behind.

Policy:

| Finding | Behaviour |
|---|---|
| Helper reports an active tunnel or the kill switch on (pf anchor `com.apple/wireguide` loaded) | **Refuse to connect.** Dialog: "Disconnect in the old LockPlus and turn off its kill switch first", plus a button that opens the Go app. |
| Helper installed but idle, or unreachable | Allow connecting, with a persistent banner: "The old LockPlus helper is still installed. Run its uninstaller (§13.3)." |
| Leftover DNS journal, no helper | Banner with instructions. We never touch root state ourselves. |

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
    var capabilities: Set<Capability>   // .openVPN, .wireGuard, .dnsOverHTTPS, .keyPassphrase
}
public struct ProvisionRequest: Codable {
    var profileID: UUID; var kind: VPNProtocolKind; var revision: UInt64
    var payload: Data                    // canonical text, ≤ 1 MiB
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
| `provision` | 1.1 MiB |
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
APP_REQ = anchor apple generic and certificate leaf[subject.OU] = "M53GHX9FAY"
          and identifier "io.github.steiale.lockplus.mac"
EXT_REQ = anchor apple generic and certificate leaf[subject.OU] = "M53GHX9FAY"
          and identifier "io.github.steiale.lockplus.mac.tunnel"
```

- Extension, in `listener(_:shouldAcceptNewConnection:)`:
  - `conn.setCodeSigningRequirement(APP_REQ)` (macOS 13+). The framework checks the requirement against the peer's audit token and invalidates the connection on mismatch.
  - The listener itself also calls `setConnectionCodeSigningRequirement(APP_REQ)` as belt and braces.
  - The extension then records `conn.effectiveUserIdentifier` for ownership checks.
- App: `conn.setCodeSigningRequirement(EXT_REQ)` before `resume()`. The app's exported `LPAppCallbackXPC` is only reachable over this already-validated connection.
- The requirement covers Developer ID and Apple Development leaf certificates for our team. Both are acceptable because both are ours. Ad-hoc signatures fail by design (L-EXT-6).
- Test: a team-signed helper binary with a different identifier, and an unsigned binary, both get `NSXPCConnectionInvalid` (§15.6).

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
- Rate limit: a token bucket per connection, 50 requests/s and burst 100. Excess gets `.rateLimited`.

### 5.5 Error model

```swift
public struct LPError: Error, Codable, Sendable {
    public var code: LPErrorCode
    public var detail: String?        // ≤ 512 chars, never contains secrets or server-controlled text
}
public enum LPErrorCode: Int, Codable, Sendable {
    // transport
    case timeout = 1, extensionUnavailable, extensionBusy, versionMismatch, unauthorizedPeer,
         payloadTooLarge, malformedRequest, rateLimited, notOwner
    // profile
    case profileNotProvisioned = 100, profileInvalid, profileRevisionStale, unsupportedDirective
    // tunnel (also used as NSError codes for cancelTunnelWithError, domain "io.github.steiale.lockplus.tunnel")
    case authFailed = 200, authRequired, authTimedOut, webAuthUnsupported, keyPassphraseRequired,
         connectTimeout, peerUnreachable, dnsResolutionFailed, engineFatal, tunDeviceFailed,
         networkSettingsFailed, legacyCryptoUnavailable, serverIdentityMismatch, conflictingVPN,
         keychainUnavailable
}
```

- The extension's `cancelTunnelWithError(NSError(domain: LPTunnelErrorDomain, code: …))` carries only the code plus a non-secret `detail` in `userInfo["lp.detail"]`.
- The app localizes every message from the code; the extension has no localization (it runs as root, in an unknown locale).
- **Assumption A-ERR-1:** `fetchLastDisconnectError` returns the provider's NSError with its domain, code and userInfo intact. Spike S12 validates this.
  - **Fallback:** the extension also stores `lastError` per profile in its state file, and the app reads it via `tunnelSnapshot`.

---

## 6. Credentials: the two-store design (L-CRED-1)

### 6.1 Ownership matrix

| Secret | App DP keychain | Extension System keychain | Written by | When |
|---|---|---|---|---|
| Payload sealing key | ✔ | — | app | first launch |
| Payload (keys inside `.conf`/`.ovpn`) | sealed file (key in DP keychain) | ✔ item `…tunnel.payload/<uuid>` | app; extension via `provisionProfile` | import, edit, reconcile |
| OVPN username/password/key passphrase | ✔ `…credentials/<uuid>` | ✔ `…tunnel.credentials/<uuid>` | app; extension via provision/`updateCredentials` | user saves, or "save" ticked in a prompt |
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

### 6.3 Extension store (System keychain)

```swift
actor SystemKeychainSecretStore {
    func put(_ kind: SecretKind, _ id: UUID, _ bytes: SecretBytes) throws(LPError)
    func get(_ kind: SecretKind, _ id: UUID) throws(LPError) -> SecretBytes?
    func delete(_ kind: SecretKind, _ id: UUID) throws(LPError)
    func deleteAll(ownerUID: uid_t) throws(LPError)
}
```

- `kSecUseDataProtectionKeychain: false`. The process is root, so the default keychain is `/Library/Keychains/System.keychain`.
- Each item is created with an explicit `SecAccess`:
  - a trusted-application list containing **only** the extension (`SecTrustedApplicationCreateFromPath(nil)`, i.e. self);
  - a partition list `teamid:M53GHX9FAY`.
  - This means the item stays readable across extension updates (same team and designated requirement) and is unreadable to any other code without an admin prompt.
- `kSecAttrLabel` is "LockPlus tunnel secret". `kSecAttrDescription` holds the profile UUID only, never the name.
- Updates are delete+add. This is the e7bbed1/cbd05ce lesson: `SecItemUpdate` never relocates an item.
- **Assumption A-KC-1:** a sandboxed root system extension can add, read and delete System-keychain items with this ACL without -25291 (`errSecNotAvailable`) or -25308 (`errSecInteractionNotAllowed`). Spike S4 validates this.
  - **Fallback:** a file per profile in the extension's sandbox container (root, 0600, under `/private/var/root/Library/Containers/<ext-id>/`), sealed with AES-GCM under a key in the System keychain. If even the key cannot be stored, it is a file key protected only by root ownership. Root ownership already defeats A1; the fallback loses only defence against an admin user.

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
| idle | `startTunnel(options)` | starting | Read `providerConfiguration`, load the payload from the System keychain, **re-validate**, check the revision. Arm the **connect deadline** (WG 45 s, OVPN 90 s). |
| starting | validation or keychain error | stopped | Fail the `startTunnel` completion with `.profileInvalid`/`.profileNotProvisioned`/`.keychainUnavailable`. |
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
| reasserting | budget exhausted, **kill switch on** | reasserting | Keep retrying at the cap. Traffic stays blocked (fail closed). The UI shows "Reconnecting (blocked)". |
| any running | `sleep()` | sleeping | `adapter.sleep()`, stop the watchdog, then call the completion (L-RC-5). |
| sleeping | `wake()` | reasserting(.wake) | `setReasserting(true)`, `adapter.wake()`. UDP sockets are recreated. Must reach `connected` within 30 s or follow the normal backoff path. |
| any | adapter `.fatal(e)` | stopped | **`cancelTunnelWithError(e)` immediately** (L-LC-1). |
| any | `stopTunnel(reason)` | stopping → stopped | `adapter.stop()` with a 5 s cap, write the session summary, then the completion. **The provider never calls `exit()` or `stopTunnel` itself** (NR §4 pitfall 10). |

Rules:
- `startTunnel`'s completion is called **exactly once**. A `CompletionOnce` wrapper asserts this in DEBUG and logs a fault in release.
- **"Connected" (L-LC-2):** the completion is called only after the data plane is up **and** `setTunnelNetworkSettings` has completed. `NEVPNStatus.connected` is therefore truthful.
- **The app has no other state source (L-LC-1, L-LC-4):** UI state comes from `NEVPNStatus`, plus `fetchLastDisconnectError` on `.disconnected`, plus `tunnelSnapshot` for detail only.

### 7.3 Data plane and fds

- **WireGuard:** WireGuardKit locates the utun fd that NE created by scanning fds for the `com.apple.net.utun_control` socket (upstream behaviour). Our fork keeps this.
- **OpenVPN:** **Decision:** openvpn3's `tun_builder_establish()` returns the **same utun fd** (found by the same scan in `ProviderHost.tunnelFileDescriptor`), after the controller has applied the settings. openvpn3's mac tun code then reads and writes utun frames (4-byte AF header) directly.
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
  - Our floor: if the profile has no `ping`/`ping-restart`/`keepalive`, normalization appends `ping 10` + `ping-restart 60` (ported from the Go `args()` floors).
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
  → [5] Normalizer     emit CANONICAL text: one directive per line, every argument double-quoted with
                       only \\ and \" escapes, inline blocks as "<name>\n…\n</name>" with body lines
                       validated (no line starting with "</"), comments dropped, ignored directives dropped,
                       floors appended (ping/ping-restart, mssfix 1300 only if no MTU directive),
                       inline <auth-user-pass> EXTRACTED to CredentialRecord and removed
  → [6] Differential   OpenVPN3Options.parse(canonical) → [[String]] must equal our directive stream
                       exactly (names, args, inline bodies); mismatch ⇒ reject "parser disagreement"
  → [7] openvpn3 eval  (extension, validateProfile XPC) ClientAPI eval_config(canonical) → EvalConfig:
                       error/message, staticChallenge(+echo), autologin, privateKeyPasswordRequired,
                       remoteHost/Port/Proto, serverList
  → ImportReport + Profile + canonical payload
```

- Steps [1]–[6] run in the app at import.
- The extension repeats [1]–[7] in `provisionProfile` **and** [1]–[6] again before every `startTunnel`.
- The engine only ever sees canonical text that two independent parsers agree on, so a tokenizer divergence cannot become a bypass.
- `openvpn3` builds without `OPENVPN_PLATFORM_*` script support and with no file access. The sandbox would deny file access anyway.

### 8.2 Directive mapping

The Go allowlist was written for openvpn **2.7**; openvpn3 supports a subset. Classification:

| Group | Directives | openvpn3 handling | Our class |
|---|---|---|---|
| Role/transport | `client`, `tls-client`, `pull`, `proto`, `remote`, `remote-random`, `resolv-retry`, `nobind`, `port`, `rport`, `connect-retry(-max)`, `server-poll-timeout`, `explicit-exit-notify`, `<connection>` | native | mapped |
| Proxy | `http-proxy host port`, `<http-proxy-user-pass>`, `http-proxy-option` | native (credentials → `proxyUsername/Password` in Config) | mapped. `socks-proxy` → unsupported |
| TLS/crypto | `ca`/`cert`/`key`/`extra-certs`/`tls-auth`/`tls-crypt`/`tls-crypt-v2`/`pkcs12` (inline), `remote-cert-tls`, `verify-x509-name`, `peer-fingerprint`, `auth`, `cipher`, `data-ciphers(-fallback)`, `ncp-ciphers`, `tls-version-min/max`, `tls-cipher`, `tls-ciphersuites`, `tls-cert-profile`, `key-direction`, `reneg-sec` | native (tls-crypt-v2 per spike gate) | mapped. `crl-verify`, `dh`, `verify-hash` → ignored with a warning |
| Compression | `comp-lzo`, `compress`, `allow-compression` | openvpn3 `compressionMode` | mapped. **Decision:** `compressionMode = "asym"` (decompress only, VORACLE) |
| DNS/routes | `dhcp-option`, `dns`, `route`, `route-ipv6`, `route-nopull`, `redirect-gateway`, `redirect-private`, `block-ipv6`, `pull-filter`, `topology`, `route-metric`, `route-gateway` | native (`PushedOptionsFilter` for pull-filter/route-nopull) | mapped |
| MTU | `tun-mtu`, `mssfix`, `link-mtu`, `fragment`, `mtu-disc` | `tun-mtu`, `mssfix` native | `fragment` → **unsupported** (reject: the server requires it); others → ignored |
| Liveness | `keepalive`, `ping`, `ping-restart`, `ping-exit`, `inactive` | native | mapped |
| Auth | `auth-user-pass` (bare or inline), `auth-nocache`, `auth-retry`, `static-challenge`, `push-peer-info` | native; `auth-retry` superseded by our prompt flow | mapped; `auth-retry` → ignored |
| Logging | `verb`, `mute`, `mute-replay-warnings` | n/a (L-OVPN-2: no verb-driven key logging in openvpn3) | ignored |
| Harmless/Windows/Linux | `persist-*`, `float`, `fast-io`, `sndbuf`, `rcvbuf`, `socket-flags`, `tun-ipv6`, `disable-occ`, `disable-dco`, `ignore-unknown-option`, `script-security`, `dns-updown disable`, `user`, `group`, `route-method`, `block-outside-dns`, `register-dns`, `ip-win32`, `dhcp-renew`, `dhcp-release`, `dhcp-pre-release`, `tap-sleep`, `providers`, `setenv`/`setenv-safe` (UV_/IV_ and listed names) | n/a | ignored (dropped from the canonical text) |
| `setenv opt X …` | inner X is checked by the allowlist, then classified as X | | as X |
| `dev`/`dev-type` | `tun` only (allowlist) | native | mapped as `dev tun` |
| Everything not on the allowlist | | | **forbidden** (import rejected; line and name shown, never the arguments) |

`EngineSupport` is a table in `LPParsing/OVPNEngineSupport.swift` with a unit test that asserts the table covers exactly the allowlist's key set.

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

| Flow | Sequence |
|---|---|
| Password (saved) | Extension loads the creds, then `provide_creds(username, password)` before `connect()`. No prompt. |
| Password (not saved / `appendOTP`) | Controller → `awaitingAuth(.userPass)` → app shows the prompt (username prefilled, password empty). With `appendOTP`, the sheet shows a saved-password field plus a "One-time code" field, and the app concatenates `base + otp` into `password`. The answer goes to `provide_creds`, then `connect()`. "Save" persists the **base** password only. |
| Static challenge (SC) | Prompt has the password field plus the challenge text as a label and a response field (echo per flag). `ProvideCreds.response = response`; openvpn3 builds `SCRV1:b64(pw):b64(resp)`. If the profile requests the **concat** format and openvpn3 lacks it (spike S8), the shim sets `password = pw + resp` and `response = ""` (Go `combineStaticChallenge` semantics). |
| Dynamic challenge (CRV1) | `connect()` returns after event `DYNAMIC_CHALLENGE` with the cookie in `info`. `OpenVPNClientHelper::parse_dynamic_challenge(cookie, dc)` → prompt `.dynamicChallenge(text: dc.challenge, echo: dc.echo)`, plus a **read-only username decoded from the cookie's base64 field** (`lockedUsername`). The answer goes to `ProvideCreds{username: <from cookie>, response, dynamicChallengeCookie: cookie}`, then a new `connect()`. The connect deadline is paused throughout. |
| AUTH_FAILED | Event `AUTH_FAILED` (`fatal` or not). If creds were stored: clear the extension's password copy, then prompt `reason: .rejected` with the server's reason text (sanitized, ≤ 200 chars) shown as secondary text. If they were not stored: prompt `.rejected`. **Never** auto-retry. After 3 consecutive rejections within 10 min: `cancelTunnelWithError(.authFailed)`. |
| Reconnect requiring auth | openvpn3 reuses session creds or an `auth-token`. If the server rejects (OTP profiles): `reasserting` → `awaitingAuth(reason: .reconnect)`, and the backoff/budget is paused. |
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
    var dns: DNSPlan, mtu: Int?, remoteAddress: String
}
public struct DNSPlan: Sendable, Equatable {
    var servers: [String]            // ordered by priority
    var searchDomains: [String]
    var splitDomains: [String]       // resolve-domains / DOMAIN when split
    var doh: URL?, dot: String?      // from `dns server N transport DoH|DoT` + sni (if supported)
}
```

| Source | Maps to |
|---|---|
| `dns server N address A …` (2.7 profile or push; a pushed priority replaces the profile's) | `servers`, ordered by ascending N; a `:port` suffix is stripped (Go `stripDNSPort`) |
| `dns server N resolve-domains d …` | `splitDomains` |
| `dns search-domains d …` | `searchDomains` |
| `dns server N transport DoH\|DoT`, `sni` | `doh`/`dot` (§10.3, spike S3) |
| `dhcp-option DNS`/`DNS6` | `servers`, **only if no `dns server` exists** (2.7 semantics, Go `dnsConfig.entries`) |
| `dhcp-option DOMAIN` | `searchDomains`; also `splitDomains` when `dnsMode == .split` |
| `dhcp-option DOMAIN-SEARCH` | `searchDomains` |
| PUSH_UPDATE changing DNS/routes | openvpn3 re-runs the tun builder (if supported; S13) → the controller re-applies settings with a short `reasserting` |

- The callbacks used: `tun_builder_set_dns_options(const DnsOptions&)` (openvpn3 ≥ 3.10). The legacy `tun_builder_add_dns_server`/`add_search_domain` are kept as fallbacks if a pinned version still emits them.
- Pushed-route hardening:
  - drop any included route that covers the server's endpoint IP (it would loop);
  - cap at 1024 routes;
  - routes with prefix length < 1 are only honoured via `redirect-gateway`.

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
- With a kill-switch profile reasserting, traffic is blocked: fail closed, by design. The menu bar shows "Blocked — reconnecting".
- **Updates while blocked (L-KS-3):** see §12.3. The tunnel is stopped and on-demand disabled before the extension is replaced, then both are restored.
- **Assumption A-KS-1:** on macOS 27, `includeAllNetworks` with the exclude flags still permits AirDrop and Xcode device debugging (`excludeDeviceCommunication`), and blocks all other non-tunnel traffic, including the app's own (Sparkle). Spike S2 validates this. **Fallback:** document the exceptions and add a per-profile "compatibility" toggle that disables `includeAllNetworks` and uses `enforceRoutes`.

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

### 10.3 DNS over HTTPS/TLS

- If `plan.doh`/`plan.dot` is set and spike S3 confirms that `NEDNSOverHTTPSSettings`/`NEDNSOverTLSSettings` work as tunnel network settings on macOS, we use them, with the same server addresses and match domains.
- **Fallback:** plain `NEDNSSettings` to the same servers. They are still inside the tunnel, so confidentiality holds as far as the VPN server. The import report notes it.

### 10.4 Wi-Fi auto-connect (on-demand)

- macOS honours on-demand rules only on the **enabled** configuration, and only one packet-tunnel configuration is active.
- **Decision:** auto-connect designates **one** profile (`AutoConnectRules.profileID`). Its manager gets:
  ```swift
  let trusted = NEOnDemandRuleDisconnect(); trusted.interfaceTypeMatch = .wiFi; trusted.ssidMatch = rules.trustedSSIDs
  let wifi = NEOnDemandRuleConnect();      wifi.interfaceTypeMatch = .wiFi
  let eth  = rules.connectOnEthernet ? NEOnDemandRuleConnect() : NEOnDemandRuleIgnore()
  eth.interfaceTypeMatch = .ethernet
  manager.onDemandRules = [trusted, wifi, eth]; manager.isOnDemandEnabled = rules.enabled
  ```
- `stayConnected` profiles get a single `NEOnDemandRuleConnect(interfaceTypeMatch: .any)`.
- **Manual connect of another profile** makes it the enabled config, which suspends the auto profile.
  - When the user later disconnects it, the app (if running) re-enables the auto profile and restores its on-demand state.
  - The UI explains: "Auto-connect resumes when you disconnect Work".
- Disconnecting the auto profile from our UI while on-demand is active sets `isOnDemandEnabled = false` until the next network change: "Paused until you join another network". Otherwise on-demand would immediately reconnect.
- **SSID → specific profile map** (Go `SSIDTunnelMap`) is app-assisted:
  - while the app runs, `CWWiFiClient` SSID events (which need Location authorization, macOS 14+) switch which profile is the on-demand profile;
  - it is off by default and requests Location only when the user enables it.
- **Assumption A-OD-1 (NR Q1):** `ssidMatch` in on-demand rules is evaluated by the system without our app holding Location authorization. Spike S1 validates this, first with a `.mobileconfig` and then with our app.
  - **Fallback:** the app-assisted mode (CoreWLAN + Location) drives `startVPNTunnel`/`stopVPNTunnel` and on-demand toggling for all rules. It is documented as requiring the app to be running.
- Adding SSIDs: the user types them; "Add current network" needs Location and is optional.
- Profiles that need interactive auth cannot be the auto profile (§8.4).

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
  - "Open LockPlus", "Settings…", "Quit LockPlus".
  - Quit asks first if a tunnel is connected: "The tunnel stays connected after quitting. Disconnect?" — Keep / Disconnect / Cancel.

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
| Latency | `measureLatency` XPC | The extension times a TCP connect (OVPN TCP), an ICMP echo via a `SOCK_DGRAM` ICMP socket, or (WG) the handshake RTT. **Only to the profile's own endpoints** (no probe oracle). |

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
- An EdDSA key pair is generated once with `generate_keys`.
  - The private key is held in a GitHub Actions environment `release` (required reviewer: Alex), with an offline backup in 1Password.
  - **Releases fail hard without it**: `generate_appcast` exits non-zero and the job fails. There is no "grace mode".
- Appcast: `https://steiale.github.io/lockplus/appcast.xml` (GitHub Pages, HTTPS).
  - Archives: `LockPlus-<ver>.zip` on GitHub Releases.
  - `SURequireSignedFeed = YES` with `SUVerifyUpdateBeforeExtraction = YES`.
  - The feed signature is generated by `generate_appcast`.
- No custom download host logic, so the redirect-host problem (8f578a8) disappears. Sparkle validates the archive signature regardless of host.
- Downgrades:
  - Sparkle offers only versions higher than the running one;
  - our `SPUUpdaterDelegate.bestValidUpdate(in:for:)` additionally filters items whose `CFBundleVersion` is less than or equal to ours;
  - the extension refuses downgrade replacement (§4.2).
- Deltas are enabled (`generate_appcast` default, keeping 3 prior versions).

### 12.2 Distribution artifacts

- `LockPlus-<ver>.zip` (for Sparkle and the cask) contains exactly `LockPlus.app`. The beta channel uses `LockPlus Native.app` (§13.4). CI asserts the top-level name (L-DIST-1).
- `LockPlus-<ver>.dmg` is made by `create-dmg` with an Applications symlink, then signed, notarized and stapled.
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
   1. Write `pendingResume = {profileID, onDemandProfileID, onDemandEnabled}` to `settings.json`.
   2. Set `isOnDemandEnabled = false` on the auto profile and save, so the system can't restart the tunnel mid-replacement.
   3. `stopVPNTunnel()` and wait for `.disconnected` (15 s timeout; on timeout continue anyway, logged). Kill-switch blocking ends here, so **the Mac is online during the replacement**.
   4. Invoke the block; Sparkle installs and relaunches.
3. The new app launches and calls `activate()`. `actionForReplacingExtension` returns `.replace`, with the tunnel already quiesced. On `.completed`, the app connects to the new versioned Mach name and runs `hello` and `reconcile`.
4. `UpdateCoordinator.resumeAfterUpdate()` restores on-demand and calls `startVPNTunnel` for `pendingResume.profileID`, then clears `pendingResume`.
5. If activation needs approval or a reboot: on-demand stays restored but the tunnel can't start. The UI shows the approval/reboot dialog. With a kill-switch profile, nothing is blocking in the meantime (the tunnel is off), and the UI says so explicitly: "Not protected until the update finishes".
6. The **first launch after any update** always runs `activate()` (L-EXT-2), so even an update installed by brew without Sparkle replaces the extension.

### 12.4 CI (GitHub Actions)

Workflows (`.github/workflows/native-*.yml`), path-filtered on `native/**`:

| Job | Runner | Steps |
|---|---|---|
| `lint` | macos-26 (Xcode 27) | swift-format lint, SwiftLint (custom rules: no secret interpolation in Logger, Backoff required, no `exit(` in Tunnel/), `version-check.sh` |
| `unit` | macos-26 | `swift test` for LockPlusCore/TunnelEngine; `xcodebuild test -testPlan Unit` |
| `fuzz-smoke` | ubuntu-latest | `swift build -c release -Xswiftc -sanitize=fuzzer,address` for the LPParsing targets; 10 min per target; corpus cached |
| `openvpn3-fuzz` | ubuntu-latest | clang libFuzzer + ASan on `OpenVPN3Options` parse; 10 min |
| `build-dev` | macos-26 | archive with Developer ID (secrets), `codesign --verify --deep --strict`, `otool -L` extension check (no AppKit/SwiftUI/Sparkle), entitlement dump diff against golden files |
| `release` (tag `native-v*`) | macos-26, environment `release` | archive, `-exportArchive` (method `developer-id`, manual signing, both profiles), notarize (`notarytool submit --wait` with an App Store Connect API key), staple, zip + dmg, notarize the dmg, `generate_appcast`, upload to GitHub Release (draft), publish the appcast to gh-pages **after** the gates below |
| `leak-harness` | self-hosted `macdev` (real NIC, Wi-Fi + Ethernet), environment `release-gate` | §15.3. Required for publishing. |
| `upgrade-test` | self-hosted, Tart macOS VM | N-1 → N (§15.5). Required for publishing. |

- Credential check: the notarization step first runs `xcrun notarytool history --keychain-profile …` or the API-key equivalent. It is never checked with `security find-generic-password` (L-DIST-2).
- **Xcode 27 export (L-DIST-2, NR Q9):** `xcodebuild -exportArchive` with an `ExportOptions.plist` (`method = developer-id`, `signingStyle = manual`, `provisioningProfiles` for both IDs).
  - Validation:
    - `spctl -a -vv -t exec`;
    - `codesign -d --entitlements :-` on both bundles, compared to golden files;
    - a smoke activation in the VM.
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
   - `ssid_tunnel_map` → `ssidProfileMap` (app-assisted mode is off until enabled).
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
| `io.github.steiale.lockplus.mac.tunnel` | `lifecycle` (incl. "first light" in `main.swift`, L-EXT-6), `xpc`, `controller`, `engine.wg`, `engine.ovpn`, `auth`, `dns`, `path`, `watchdog`, `keychain` |

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
- **EngineSupport** covers exactly the allowlist.
- **WG parser and validator:** port `parser_test.go` and `validator_dns_test.go`; add wg-quick inline-comment, bare-IP and CRLF cases.
- **Legacy keychain decode:** b64, hex and plain fixtures (`keychain_darwin_test.go` vectors).
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
- Keychain: provision, read at connect, update, delete, `wipeAll`; ACL survives an extension update (S4).
- WG against a test server (docker on a VPS): connect, data-plane-up timing, endpoint failover (first A record blackholed), MTU applied (`ifconfig utunN`).
- OVPN against test servers:
  - UDP, TCP, tls-crypt-v2;
  - CBC-only (`cipher AES-256-CBC`, no NCP);
  - BF-CBC;
  - password, SC (SCRV1 and concat), CRV1 (a server plugin that issues a CRV1 with a username), AUTH_FAILED → re-prompt;
  - WEB_AUTH → `.webAuthUnsupported` within 2 s;
  - a server pushing `dns server`, `dhcp-option`, PUSH_UPDATE, plus profile `pull-filter ignore "dhcp-option"`.
- **Real profiles (spike gate and regression):** BHP (Sophos) and AllService, run manually on each release candidate. Credentials are never in CI.
- L-LC-1: `kill -SEGV` the wireguard-go goroutine via the debug XPC `debugInjectFault(.wgDeviceClose)` (DEBUG builds only) → status leaves `.connected` ≤ 5 s.

### 15.3 Leak harness (L-KS-1, L-KS-4, L-DNS-1)

`Tools/leak-harness/lp-leakcheck`:
- runs as root on the self-hosted Mac;
- drives the app through a DEBUG-only automation XPC, or through `scutil --nc` where sufficient;
- captures on the physical interfaces (`en0` Wi-Fi, `en7` USB Ethernet) with BPF.
- **Pass criterion for every window:** zero packets on a physical interface except
  - to or from the VPN endpoint (IP:port, proto);
  - DHCP, ARP, ND, RA;
  - with `allowLAN`, link-local and connected-subnet traffic.

| Case | Scenario | Assertion |
|---|---|---|
| LK-01 | Connected baseline (WG UDP; OVPN UDP) | criterion holds for 60 s of `curl`/`dig`/`ping` load |
| LK-02 | `kill -9` the extension while connected (kill switch on) | no leak until reconnect or block; status leaves `.connected` ≤ 5 s (L-LC-1) |
| LK-03 | Reconnect: the server drops (endpoint blackholed by test-router rule), 3 min | blocking continues during `reasserting` (L-KS-1) |
| LK-04 | Sleep/wake (`pmset sleepnow` + `pmset schedule wake`) | no packets before the tunnel is up; reconnects ≤ 30 s (L-RC-5) |
| LK-05 | Wi-Fi → Ethernet → Wi-Fi switch (`networksetup -setnetworkserviceenabled`) | no leak; reasserting → connected ≤ 20 s (L-RC-1) |
| LK-06 | Fragments and large packets: `ping -s 4000` through the tunnel, 1 GB SMB copy, RDP session for 5 min (L-KS-4) | no stalls; throughput ≥ 70 % of baseline |
| LK-07 | OpenVPN over TCP: LK-01..06 repeated with a `proto tcp` profile | same |
| LK-08 | DNS: `scutil --dns` shows the tunnel resolver first with a catch-all; `dig @8.8.8.8 example.com` and `dig @<ISP resolver>`; system resolver lookups | zero UDP/TCP 53 and 853 on the physical NICs; queries observed on utun |
| LK-09 | IPv6: a v4-only tunnel on a dual-stack LAN | no v6 egress on the physical NIC (includeAllNetworks) |
| LK-10 | Sparkle update N-1 → N with kill switch on (L-KS-3) | the Mac is online during replacement; the tunnel resumes; no leak during "resumed" connect |
| LK-11 | `kill -9` the extension with the kill switch off, then `scutil --dns` (L-DNS-1) | resolver config back to baseline ≤ 5 s |
| LK-12 | Split profile with route protection: a more specific LAN route injected | tunnel routes are still honoured |
| LK-13 | TN3165 matrix (manual, recorded): AirDrop, Continuity/Handoff, Internet Sharing, Xcode device debugging, AirPlay | expected outcome per policy flag documented |

### 15.4 Fuzzing

libFuzzer targets on Linux in CI (10 min) and nightly on a self-hosted machine (8 h):
- `fuzz_ovpn_tokenizer`
- `fuzz_ovpn_import` (tokenizer → allowlist → normalizer; asserts the normalizer output re-tokenizes to the same stream)
- `fuzz_ovpn_differential` (C++ harness linking the Swift-exported C API and `OpenVPN3Options`)
- `fuzz_wg_parser`
- `fuzz_crv1_cookie`
- `fuzz_zip_import` (with ZIPFoundation)
- `fuzz_lpwire_decode`

Crashes become regression fixtures in `Tests/Fixtures/fuzz/`.

### 15.5 Update tests (L-UPD-1)

- A Tart VM image with macOS 15 and one with macOS 27.
- Install N-1 from the published DMG, approve the extension (scripted via MDM profile in the VM), import the fixtures, connect with the kill switch on, then point the appcast to staging N.
- Assert:
  - `systemextensionsctl list` shows N activated and enabled, with N-1 terminated;
  - the tunnel resumes;
  - profiles, credentials (connect without prompt) and history are intact;
  - no dialog other than Sparkle's.
- Also: a downgrade attempt is refused, and an install of N over N-1 by brew alone (no Sparkle) is followed by a launch.

### 15.6 Security test checklist (each release; Fable reviews the code, these verify behaviour)

- [ ] XPC rejects an unsigned and a wrong-identifier peer; the app rejects a fake extension listener (a team-signed binary registering a lookalike name is impossible without our provisioning; tested with a DEBUG override).
- [ ] Profile ownership: a second macOS user cannot provision or remove another user's profile over XPC.
- [ ] Every forbidden directive is rejected at import **and** at provision, with the app bypassed by a test client.
- [ ] No secret strings in: the unified log (`log show --predicate 'subsystem BEGINSWITH "io.github.steiale.lockplus"' --info --debug` with private data enabled via a configuration profile on the test Mac), the diagnostics bundle, crash reports (forced crash in DEBUG), `defaults read`, NE prefs (`/Library/Preferences/com.apple.networkextension.plist`).
- [ ] Sealed payload files are unreadable without the DP key; deleting the key yields "profiles locked" UI, not a crash.
- [ ] System keychain items: `security find-generic-password` as admin prompts; other apps cannot read them silently.
- [ ] Export writes 0600 with `O_NOFOLLOW` (a symlink at the destination is refused); LAContext is required.
- [ ] Zip bomb, 501-entry zip, path-traversal names, huge QR: all rejected within limits.
- [ ] Sparkle: a tampered archive, an unsigned feed and a lower version are each refused.
- [ ] Extension binary links no AppKit, SwiftUI or Sparkle; no `get-task-allow` in release entitlements.
- [ ] A WEB_AUTH server, an encrypted key without a passphrase, and a proxy-auth profile each produce a visible error ≤ 5 s (L-OVPN-4).

---

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

**Update:** §12.3.

**Uninstall:** §4.4.

**Profile edit while connected:**
1. Save seals revision n+1 and provisions the extension (new revision stored).
2. The connected session keeps running revision n. The UI shows "Reconnect to apply".
3. The next connect loads n+1.

---

## 17. Spike plan (answers NR §6), with go/no-go

Spike duration: 5 days. Each spike has an owner checklist and a written result appended to this document as §17.x "Result".

| ID | NR Q | Question | Method | Go criterion | Fallback / no-go action |
|---|---|---|---|---|---|
| S1 | Q1 | `ssidMatch` without Location on 15/27 | `.mobileconfig` with VPN on-demand SSID rules; then our app with no Location grant; toggle Wi-Fi networks | On-demand connects and disconnects per SSID on both OSes with no Location prompt | App-assisted mode (§10.4) for all SSID rules |
| S2 | Q2 | `includeAllNetworks` + exclude flags on 27: AirDrop, Xcode device, Sparkle while blocked; rename-while-connected doesn't restart | Manual matrix LK-13; save the manager with a changed `localizedDescription` while connected | AirDrop and Xcode work with `excludeDeviceCommunication`; Sparkle check fails gracefully while reasserting; rename keeps the session | Document exceptions; per-profile compatibility toggle; defer rename |
| S3 | Q3 | `NEDNSOverHTTPSSettings` in tunnel settings | WG test profile with a DoH resolver inside the tunnel | Queries go to DoH (captured on utun as TLS/443 to the resolver), none in plain text | Plain `NEDNSSettings` |
| S4 | Q4 | System keychain from the sandboxed root extension | Add/read/delete with the §6.3 ACL; update the extension; read again | No -25291/-25308; no prompts; readable after replacement | Sealed container file (§6.3) |
| S5 | Q5 | XPC via `NEMachServiceName` with a per-version name | App ↔ extension `hello` while the tunnel is down and up; replace the extension while disconnected; check `launchctl print` for stale registrations | XPC works in both states; the new name is reachable after replacement; no side effects | Fixed name + mandatory stop-before-replace |
| S6 | Q6 | TN3179 exemption for the root extension | WG endpoint on a LAN IP (192.168.x); no Local Network prompt | Connects with no prompt | Document; the app requests Local Network if needed for diagnostics only |
| S7 | Q7 | WireGuardKit (Go runtime) + openvpn3 (asio/OpenSSL) in one process | One extension; alternate 50 WG/OVPN connects; ASan build; memory over 1 h | No crashes, no symbol clashes (`nm` check for duplicate OpenSSL/BoringSSL symbols), RSS < 50 MB steady | Two system extensions (`…tunnel.wg`, `…tunnel.ovpn`) behind the same `TunnelAdapter`; the app picks the provider bundle ID per profile |
| S8 | Q8 | openvpn3 CRV1 and SC through the shim | Test server with a CRV1 plugin; SC with the echo/concat variants; BHP and AllService real profiles | All four work; the username from the CRV1 cookie is used | **No-go for OpenVPN-in-NE** if CRV1 or SC cannot work: ship WG-only native (phase 2), keep the Go app as the OpenVPN line, re-evaluate |
| S9 | Q9 | Xcode 27 Developer ID export end to end | `-exportArchive`, notarize, install in a clean VM, activate, connect | Extension loads (no "Plugin failed") | Inside-out re-sign script |
| S10 | Q10 | Sparkle update replacing the extension while connected and with the kill switch on | Staged appcast in the VM, §12.3 flow | Tunnel resumes; the Mac is never offline > 15 s; no XPC breakage | Require disconnect before "Install and relaunch" with an explicit dialog |
| S11 | — | openvpn3 on the NE utun fd (§7.3) | Return the scanned fd from `tun_builder_establish` | Traffic flows; throughput ≥ 300 Mbit/s on M1 | socketpair bridge |
| S12 | — | `fetchLastDisconnectError` passes custom domain/code/userInfo | Cancel with a custom NSError; read it in the app | Domain and code are intact | `tunnelSnapshot.lastError` |
| S13 | — | openvpn3: tls-crypt-v2, CBC-only server, BF-CBC with `enableLegacyAlgorithms`, PUSH_UPDATE, `dns` options, `pull-filter` | Test servers | All connect; DNS options arrive via `tun_builder_set_dns_options`; pull-filter honoured | Per item: mark unsupported at import with a clear message (PUSH_UPDATE: reconnect to apply) |

**Overall spike gate (NR §3 "Spike gate"):** BHP and AllService connect, CRV1 and SC work, a CBC-only server works, and tls-crypt-v2 works. Failing S8 or S13 (tls-crypt-v2/CBC) means OpenVPN-in-NE is no-go as above. Failing S7 means the two-extension fallback, about 3 more days.

---

## 18. Phased implementation plan

Estimates are in developer-days. Every phase's Definition of Done includes:
- all unit tests green;
- review by lens: Sonnet first pass, Opus architecture, and a **Fable security pass on extension, keychain, parser and XPC code**;
- **every finding fixed**;
- this document updated where reality differed.

| Phase | Scope | Milestone / Definition of Done |
|---|---|---|
| **P1 Spike** (5) | §17. Throwaway code in `native/spike/`. | M1: every spike has a written result and decision; the OpenVPN go/no-go recorded; this document amended. |
| **P2a Skeleton** (6) | Xcode project, xcconfigs, version-check, entitlements, Developer ID signing for dev, `SystemExtensionManager` (§4) with every outcome, XPC skeleton with peer validation and timeouts (§5), CI lint/unit/build-dev, debug menu. | M2: a fresh VM installs a notarized dev build, approves, `hello` round-trips; a wrong-signature client is rejected; the extension `otool -L` check passes. |
| **P2b WireGuard engine** (8) | WG parser/validator port, fork patches 1–5, `TunnelController` state machine with fakes, `WireGuardAdapterImpl`, `NetworkSettingsBuilder`, path, sleep, watchdog, backoff, stats/sessions. | M3: WG connects with data-plane-up semantics; LK-01..05, LK-08, LK-11 pass for WG; the state-machine suite is complete. |
| **P2c Storage and credentials** (6) | `ProfileStore` (sealed payloads), `CredentialStore` (DP), `SystemKeychainSecretStore`, provision/reconcile, kill-switch policy (§10.1), DNS (§10.2), `DNSVerifier`, Go migrator (WG part), minimal UI (list, connect, import file), DMG, release workflow, `lockplus-native` cask. | **M4: WireGuard beta.** Alex's Flo VPN runs a week on the beta; the leak harness passes for WG; the N-1 → N update test passes (beta1 → beta2). |
| **P3 OpenVPN** (20–30) | Tokenizer/allowlist port with shared fixtures, normalizer, `OpenVPN3Options` differential, the OpenSSL static build, `OpenVPN3Shim` (client, TunBuilder, events, logs, redactor), `OpenVPNAdapterImpl`, auth UI (§8.4), import report UX, legacy crypto, DNS mapping, OVPN migration with legacy keychain, fuzzers. | **M5: OpenVPN beta.** BHP and AllService connect (password, SC, CRV1, re-prompt); the full leak harness passes including LK-07; the 8 h fuzz run is clean; the Fable review of shim and parser is fully fixed. |
| **P4 UI parity** (15–25) | MenuBarController (§11.3), detail, editor with highlighting, statistics, history, logs, diagnostics, auto-connect, settings, onboarding, String Catalogs ×4, accessibility audit, Sparkle (§12), `SMAppService.mainApp`, in-app Uninstall, diagnostics bundle. | **M6: release candidate.** Parity checklist (§11.5) complete; VoiceOver pass; de/ko/ja reviewed; the security checklist (§15.6) passes; the update test passes on 15 and 27. |
| **P5 Cutover** (5–10) | Go v1.2.0 Farewell (§13.3), cask transition (§13.4), zap audits, README and screenshots. | **M7: GA.** Native 2.0.0 is in the `lockplus` cask; Go helper removal verified on Alex's two Macs (pf anchors gone, DNS restored, `launchctl print` clean); no data loss in the migration report. |

Total: 65–95 days, consistent with NR §5.

---

## 19. Traceability: L-* requirements → design → test

| Requirement | Satisfied by (section) | Test |
|---|---|---|
| L-LC-1 no zombie tunnels | §7.2 (`fatal` → `cancelTunnelWithError`), §11.2 (status only from NEVPNStatus + `fetchLastDisconnectError`) | §15.1 state machine "fatal → cancel"; §15.2 fault injection ≤ 5 s; LK-02 |
| L-LC-2 connected = data plane up | §7.2 completion rule, §9.3 handshake, §8.4/§7.3 OVPN CONNECTED + settings | §15.1 completion-once/order tests; §15.2 WG/OVPN connect timing |
| L-LC-3 timeouts on every cross-process call | §5.4 per-method timeouts, liveness rule; §5.1 connect is not XPC | §15.1 XPC wire timeout tests; §15.2 slow-connect test (server delays 60 s; no "dead" UI) |
| L-LC-4 one source of truth | §10.1 policy in the NE config; §11.2 stores | §15.1 store tests; LK-03 with connects from the menu bar, window and on-demand |
| L-RC-1 path changes | §7.4 PathWatcher → reasserting | LK-05 |
| L-RC-2 dead peer | §7.5 watchdog, OVPN keepalive floors | §15.1 watchdog tests; LK-03 |
| L-RC-3 backoff | §7.6 `Backoff`, server pause honoured, no auth auto-retry | §15.1 backoff tests; lint rule |
| L-RC-4 auth during reconnect | §7.2 deadline pause, §8.4 promptID | §15.1 auth-pause and stale-answer tests; §15.2 OTP reconnect |
| L-RC-5 sleep/wake | §7.4 | §15.1; LK-04 |
| L-KS-1 verify behaviour | §15.3 harness as a release gate (§12.4) | LK-01..13 |
| L-KS-2 never toggle while connected | §10.1 `updatePolicy` throws `.mustBeDisconnected`; UI disables | §15.1 ProfileStore test; UI test |
| L-KS-3 updates while blocked | §12.3 quiesce → replace → resume | LK-10; §15.5 |
| L-KS-4 fragments and TCP | §9.3 MTU/MSS floors; harness cases | LK-06, LK-07 |
| L-DNS-1 crash leaves no state | §10.2 (NE-owned DNS) | LK-11 |
| L-DNS-2 every pushed form | §8.5 mapping table, openvpn3 pull-filter | §15.1 DNS table tests; §15.2 push server; S13 |
| L-DNS-3 diagnostics fail closed | §10.2 `DNSVerifier` (`.unknown` ≠ safe) | §15.1 verifier tests with unreadable/mismatch fixtures |
| L-MTU-1 MTU, endpoints, floors | §9.3, §8.1 floors | §15.2 MTU applied, endpoint failover; LK-06 |
| L-OVPN-1 allowlist + identical parser | §8.1 pipeline (port + canonical + openvpn3 differential), §8.2 | §15.1 shared fixtures and differential; §15.4 fuzzing |
| L-OVPN-2 2.7 traps | §8.6 legacy crypto, §8.7 no verb logging, OpenSSL legacy provider | §15.2 CBC-only and BF-CBC servers; log grep; S13 |
| L-OVPN-3 auth flows | §8.4 | §15.2 password/SC/CRV1/AUTH_FAILED/WEB_AUTH; S8 |
| L-OVPN-4 errors reach the user | §5.5 codes, §11.7 | §15.6 last item; S12 |
| L-CRED-1 keychain location | §6 (DP app store, System ext store, raw `Data`, UUID keys, no `passwordReference`) | §15.2 keychain tests; S4; §15.6 |
| L-MB-1 menu bar | §11.3 | §15.1 RateMeter; UI tests (menu rebuilt on open, item removed on quit, visibility banner) |
| L-EXT-1 one dialog, no loops | §4.2 table | §15.2 activation outcomes |
| L-EXT-2 activate every launch, bump both keys | §4.2, §2.6 | version-check CI; §15.5 |
| L-EXT-3 replacement while connected | §4.3 per-version Mach name, §12.3 stop first | S5, S10; §15.5 |
| L-EXT-4 uninstall | §4.4 | §15.2: after uninstall, `systemextensionsctl list` is empty and no keychain items or managers remain |
| L-EXT-5 no AppKit in extension | §2.2 dependency rules | CI `otool -L` check |
| L-EXT-6 Developer ID dev builds, debug loop | §2.4, §2.7, §4.2 debug menu, §14.1 first light | M2 |
| L-UPD-1 updater | §12.1, §12.3, §4.2 downgrade refusal | §15.5; §15.6 Sparkle items |
| L-DIST-1 cask hygiene | §12.2 zip name, zap audit, absolute paths, `auto_updates` | CI zip-name assert; tap grep job |
| L-DIST-2 notarization and export | §12.4 | S9; release workflow |
| L-MIG-1 copy-only migration + Go uninstaller | §13 | §15.2 migration fixtures (a Go data dir snapshot) with a checksum showing the source is untouched; M7 verification |

NR §3 "Security posture to keep":
- import caps (§3.5);
- names validated (§3.1);
- exports 0600 `O_NOFOLLOW` (§15.6);
- XPC peer validation (§5.3);
- no web views (§11.4);
- mandatory reviews (§18).

NR §4 pitfalls 1–15 map to §12.4, §2.4, §2.2, §6, §4.3, §2.6, §4.4, §10.1, §12.3, §7.2, §7.4, §10.2, §10.4, §11.1/§13.1 and §9.2, respectively.

---

## 20. Open risks

1. **OpenVPN-in-NE viability (S8/S13).** If openvpn3 can't do CRV1/SC, or the corporate servers need features openvpn3 lacks, the OpenVPN line stays on Go for longer.
2. **System keychain from a sandboxed root extension (S4).** This is thinly documented. The fallback is weaker only against an admin user.
3. **Per-version Mach names and launchd (S5).** Unknown accumulation behaviour across many dev builds. The mitigation is a periodic deactivate/activate in dev.
4. **On-demand + interactive auth.** OTP profiles can't auto-connect. Users who expect this get a clear UI restriction, not a feature.
5. **SSID rules without Location (S1).** If they need Location, auto-connect depends on the app running for SSID-specific behaviour.
6. **`includeAllNetworks` side effects on 27 (S2).** Expect user reports about AirDrop, Continuity and Sidecar. The compatibility toggle exists for this.
7. **Fork maintenance.** WireGuardKit and openvpn3/OpenSSL are three upstreams we must track. The monthly watch job and pinned toolchains mitigate this, but the bus factor is 1.
8. **Memory hygiene limits.** XPC, SwiftUI and openvpn3 make copies we can't zero. This is accepted and documented, not solved.
