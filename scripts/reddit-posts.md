# Reddit promotion posts — WireGuide+

---

## r/MacApps
**Title:** I forked an open-source WireGuard client and added the features I actually wanted

Been running WireGuard on my home server for about a year. On Mac your options are basically the
App Store client (functional but really bare-bones) or tunnelblick (which is OpenVPN, not the
same thing). 

Found an open-source project called [WireGuide by korjwl1](https://github.com/korjwl1/wireguide)
that had exactly the right idea — native Mac UI, no Electron, clean card layout. Forked it and
spent a few weekends adding the stuff I kept wishing was there.

What I ended up adding on top of the original:

- Wi-Fi auto-connect (connect/disconnect automatically when joining specific networks)
- Latency monitor in the card header
- Connection history with bytes per session
- Kill switch — blocks all traffic if the tunnel drops
- DNS leak protection
- Built-in log viewer and DNS leak test
- Per-tunnel notes

It's signed and notarized so no Gatekeeper nonsense. Homebrew or a plain DMG if you prefer
drag-to-Applications.

Would love feedback if anyone gives it a shot. Still actively working on it.

https://github.com/steiale/wireguide

---

## r/selfhosted · r/homelab
**Title:** Built a macOS WireGuard client that actually has Wi-Fi auto-connect and a kill switch

I self-host my own WireGuard server and the Mac client situation has always been a bit annoying.
The App Store client works fine but it's missing a bunch of things that feel pretty basic once
you're used to them — automatic connect on untrusted networks, a kill switch, seeing your DNS
isn't leaking, etc.

I found a great open-source starting point ([WireGuide by korjwl1](https://github.com/korjwl1/wireguide)
— all credit to them for the foundation) and built out what was missing for my own use case.
Figured I'd share since this crowd probably has the same frustrations.

The stuff I care about most that's in there:

- **Wi-Fi auto-connect** — connect to a specific tunnel when joining an untrusted network,
  disconnect on your home SSID
- **Kill switch** via macOS `pf` — drops all traffic if the tunnel goes down
- **DNS leak test** built in, DNS lock to tunnel servers
- **Auto-reconnect** after sleep/wake
- Live speed graph and latency per tunnel
- Connection history

Architecture nerd stuff if you care: it's a two-binary setup — a GUI process (never root) and a
minimal LaunchDaemon helper that handles the actual WireGuard interface. The split was necessary
because macOS 26 broke single-binary approaches where the same binary runs as both GUI and root
daemon.

Apple Silicon, macOS 13+, free, MIT licensed.

https://github.com/steiale/wireguide

---

## r/WireGuard
**Title:** Wrote a macOS client with Wi-Fi auto-connect, kill switch, and DNS leak test — sharing in case it's useful

Been self-hosting WireGuard for a while and wanted a Mac client that felt complete. The official
App Store one is fine for basic use but I kept hitting its limits.

Started from [WireGuide by korjwl1](https://github.com/korjwl1/wireguide) — great foundation,
full credit to them — and extended it for my own use. Sharing here since this community probably
has similar needs.

Key additions over the original: Wi-Fi auto-connect rules, kill switch (pf), DNS lock + leak
test, connection history, auto-reconnect on wake, log viewer. Multiple tunnels work
simultaneously.

https://github.com/steiale/wireguide

Apple Silicon / macOS 13+. Free, open source.

---

## Hacker News — Show HN
**Title:** Show HN: WireGuide+ – macOS WireGuard client (fork) with Wi-Fi auto-connect and privilege-separated daemon

Show HN: WireGuide+ — https://github.com/steiale/wireguide

I self-host WireGuard and wanted a Mac client that actually felt finished. Found
[WireGuide by korjwl1](https://github.com/korjwl1/wireguide), a Wails (Go + Svelte) wrapper
around wireguard-go, and forked it. The original did the hard part — I mostly added features and
fixed some macOS-specific rough edges.

The most interesting problem I ran into: macOS 26 beta tightened framework `+load` behavior.
WebKit and QuartzCore crash before any Go code runs when the binary is exec'd as root without a
window server. The obvious fix is to just not import those frameworks in daemon mode, but with a
single binary that's not straightforward. Ended up doing a proper two-binary split: GUI process
(Wails/AppKit, never root) + minimal helper (IOKit only, runs as LaunchDaemon), talking JSON-RPC
over a Unix socket. Overkill maybe, but it solved the problem cleanly and the privilege separation
is actually the right design anyway.

A few other things that were non-obvious:
- Sleep/wake in a root daemon needs IORegisterForSystemPower. NSWorkspace notifications are dead
  in a non-GUI bootstrap namespace — cost me a day.
- `cp` preserves quarantine xattr. Gatekeeper blocks your Developer ID-signed binary in
  /Library/PrivilegedHelperTools unless you strip it after copy.
- Don't send a Shutdown RPC to a launchd-managed daemon before reinstalling it. The 10-second
  ThrottleInterval will stall your reinstall loop.

Features I added: Wi-Fi auto-connect, kill switch (pf), DNS leak protection, live speed graph,
latency monitor, connection history, log viewer, auto-update. Apple Silicon, macOS 13+, MIT.

Install: `brew tap steiale/tap && brew install --cask wireguide-plus`
DMG: https://github.com/steiale/wireguide/releases/latest
