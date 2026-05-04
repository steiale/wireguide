<p align="center">
  <img src="docs/appicon.png" width="128" alt="WireGuide+" />
</p>

<h1 align="center">WireGuide+</h1>

<p align="center">
  A macOS WireGuard VPN client with a clean card-based UI, kill switch, and auto-reconnect.<br>
  Signed, notarized, and distributed via Homebrew.
</p>

<p align="center">
  <a href="https://github.com/steiale/wireguide/releases/latest"><img src="https://img.shields.io/github/v/release/steiale/wireguide?style=flat-square" alt="Release" /></a>
  <a href="https://github.com/steiale/wireguide/stargazers"><img src="https://img.shields.io/github/stars/steiale/wireguide?style=flat-square" alt="Stars" /></a>
  <a href="#install"><img src="https://img.shields.io/badge/homebrew-tap-blue?style=flat-square" alt="Homebrew" /></a>
  <img src="https://img.shields.io/badge/platform-macOS%2013%2B%20%E2%80%A2%20Apple%20Silicon-lightgrey?style=flat-square" alt="Platform" />
  <a href="LICENSE"><img src="https://img.shields.io/github/license/steiale/wireguide?style=flat-square" alt="License" /></a>
  <a href="https://ko-fi.com/steiale"><img src="https://img.shields.io/badge/Ko--fi-buy%20me%20a%20coffee-FF5E5B?style=flat-square&logo=ko-fi&logoColor=white" alt="Ko-fi" /></a>
</p>

---

<table>
  <tr>
    <td align="center"><img src="docs/screenshots/01-tunnels.png" width="380" /><br><sub>Tunnel overview</sub></td>
    <td align="center"><img src="docs/screenshots/02-expanded.png" width="380" /><br><sub>Expanded tunnel — config details</sub></td>
    <td align="center"><img src="docs/screenshots/03-connected.png" width="380" /><br><sub>Connected — live stats &amp; speed graph</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="docs/screenshots/05-dns-leak.png" width="380" /><br><sub>DNS leak test</sub></td>
    <td align="center"><img src="docs/screenshots/07-history.png" width="380" /><br><sub>Connection history</sub></td>
    <td align="center"><img src="docs/screenshots/08-settings.png" width="380" /><br><sub>Settings</sub></td>
  </tr>
</table>

---

## Features

| Feature | Description |
|---------|-------------|
| **Card-based UI** | Each tunnel is an expandable card — connect, view live stats, edit config, and manage in one place |
| **Live Speed Graph** | Real-time RX/TX bandwidth chart updates every second while connected |
| **Latency Monitor** | Per-tunnel ping latency displayed live in the card header |
| **Connection History** | Per-tunnel session log with timestamp, duration, and bytes transferred |
| **Wi-Fi Auto-Connect** | Automatically connect or disconnect tunnels when joining specific Wi-Fi networks |
| **Multi-Tunnel** | Connect multiple WireGuard tunnels simultaneously with independent per-tunnel state |
| **Auto-Reconnect** | Per-tunnel reconnect on sleep/wake and network changes |
| **System Tray** | Connection status in the menu bar, 1-click connect/disconnect without opening the window |
| **Kill Switch** | Blocks all non-VPN traffic via macOS `pf` when the tunnel drops (optional) |
| **DNS Protection** | Locks DNS to the active tunnel's servers to prevent leaks (optional) |
| **Config Editor** | Create, edit, import, and export `.conf` files — drag-and-drop and QR code import supported |
| **Per-tunnel Notes** | Attach a freeform note to any tunnel — visible in the expanded card |
| **First-Run Wizard** | Automatically discovers existing WireGuard configs from the Mac App Store app |
| **Conflict Detection** | Warns about route conflicts when multiple tunnels have overlapping subnets |
| **Diagnostics** | Built-in ping test, DNS leak test, and route table visualization |
| **Log Viewer** | Live log stream from both GUI and helper, filterable by level (Debug / Info / Warn / Error) |
| **Auto-Update** | Checks GitHub Releases on launch; one-click update or `brew upgrade --cask wireguide-plus` |
| **Dark / Light / System** | Follows macOS appearance — navy/teal theme optimized for both modes |
| **Signed & Notarized** | Developer ID signed and Apple-notarized — no Gatekeeper warnings, no quarantine |

---

## Requirements

**Apple Silicon (M1 or later) only.** Intel Macs are not supported.

## Install

### Homebrew — recommended

```bash
brew tap steiale/tap
brew install --cask wireguide-plus
```

To update:

```bash
brew upgrade --cask wireguide-plus
```

### DMG — direct download

Download the latest `.dmg` from [Releases](https://github.com/steiale/wireguide/releases/latest), open it, and drag `WireGuide+.app` to `/Applications`. The app is signed and notarized — no Gatekeeper warnings.

### ZIP — manual

Download the latest `.zip` from [Releases](https://github.com/steiale/wireguide/releases/latest), unzip, and move `WireGuide+.app` to `/Applications`.

---

## Build from Source

```bash
brew install go node
go install github.com/go-task/task/v3/cmd/task@latest
go install github.com/wailsapp/wails/v3/cmd/wails3@latest

wails3 task darwin:package
open bin/wireguide-plus.app
```

---

## Architecture

```mermaid
graph LR
    subgraph GUI["GUI Process (unprivileged)"]
        A1[Wails + Svelte]
        A2[Config editor]
        A3[System tray]
        A4[Diagnostics]
    end

    subgraph Helper["Helper Process (root)"]
        B1[wireguard-go + wgctrl]
        B2[TUN / routing / DNS]
        B3[Kill switch / firewall]
        B4[Reconnect monitor]
        B5[Route monitor]
    end

    GUI <-->|"JSON-RPC over Unix socket"| Helper
```

- **Two binaries** — `wireguide-plus` (GUI, Wails/AppKit) and `wireguide-plus-helper` (daemon, IOKit only); the helper runs as a root LaunchDaemon without a window server
- **Privilege separation** — GUI is unprivileged; helper runs as root LaunchDaemon
- **IPC** — JSON-RPC over Unix domain socket

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.24+ |
| GUI | [Wails v3](https://wails.io) |
| Frontend | Svelte + Vite |
| WireGuard | [wireguard-go](https://git.zx2c4.com/wireguard-go) + [wgctrl-go](https://github.com/WireGuard/wgctrl-go) |
| Firewall | macOS `pf` |

---

## Fork

WireGuide+ is a fork of [WireGuide](https://github.com/korjwl1/wireguide) by korjwl1, extended with a redesigned UI, additional features, and macOS notarization.

---

## License

[MIT](LICENSE)
