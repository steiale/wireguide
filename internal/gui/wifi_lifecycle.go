// Wi-Fi auto-connect lifecycle.
//
// On launch, load the persisted rules and start a wifi.Monitor that polls
// the SSID every 5 s. When the SSID changes, rules.Action(newSSID) tells us
// whether to disconnect (trusted network — VPN not needed), connect to a
// specific tunnel (mapped SSID), or do nothing.
//
// All connect/disconnect calls go through the same IPC client holder used
// by the rest of the app, so a helper restart swaps cleanly. Save() in the
// app layer notifies us via SetWifiRulesNotifier so the live monitor picks
// up new rules without an app restart.
package gui

import (
	"log/slog"
	"sync"

	wgapp "github.com/steiale/wireguide/internal/app"
	"github.com/steiale/wireguide/internal/storage"
	"github.com/steiale/wireguide/internal/wifi"
)

// wifiLifecycle owns the live wifi.Monitor and applies rule changes.
type wifiLifecycle struct {
	mu            sync.Mutex
	monitor       *wifi.Monitor
	tunnelService *wgapp.TunnelService
	store         *storage.WifiRulesStore
}

// startWifiLifecycle loads persisted rules, starts the monitor, and registers
// the rules-change hook so SaveWifiRules updates the live monitor in place.
// Returns the lifecycle so the caller can stop it on shutdown.
//
// connect/disconnect actions go through tunnelService (the same Wails
// service the frontend calls) rather than issuing raw IPC requests directly,
// so SSID-triggered auto-connect gets the exact same protocol dispatch
// (WireGuard vs OpenVPN), MarkInflight/UnmarkInflight bracketing (without
// it, the health monitor could misread a slow OVPN auto-connect as a dead
// helper and kill the in-flight RPC mid-connect — the same root cause as
// the previously-fixed "helper dies 22-30s after connect" bug), and history
// recording that TunnelService.Connect/DisconnectTunnel already provide.
func startWifiLifecycle(tunnelService *wgapp.TunnelService, store *storage.WifiRulesStore) *wifiLifecycle {
	lc := &wifiLifecycle{tunnelService: tunnelService, store: store}

	rules, err := store.Load()
	if err != nil {
		slog.Warn("wifi rules: load failed, starting with defaults", "error", err)
		rules = wifi.DefaultRules()
	}

	lc.monitor = wifi.NewMonitor(rules, lc.handleSSIDChange)
	lc.monitor.Start()

	// Register the runtime-update hook so the Wails service can hand new
	// rules to the running monitor without restarting the app.
	wgapp.SetWifiRulesNotifier(func(r *wifi.Rules) {
		lc.mu.Lock()
		defer lc.mu.Unlock()
		if lc.monitor != nil {
			lc.monitor.UpdateRules(r)
			slog.Info("wifi rules updated at runtime",
				"enabled", r.Enabled,
				"trusted", len(r.TrustedSSIDs),
				"mapped", len(r.SSIDTunnelMap))
		}
	})

	return lc
}

// stop halts the monitor goroutine. Idempotent.
func (lc *wifiLifecycle) stop() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.monitor != nil {
		lc.monitor.Stop()
	}
}

// handleSSIDChange is invoked from the monitor's poll goroutine. We re-load
// the rules each time (cheap — single JSON file) so the action reflects the
// latest persisted state even if the in-memory monitor lagged a notify.
//
// Errors here MUST be logged, not returned — the wifi monitor has no caller
// to surface them to. A failed connect on SSID change should not crash the
// process.
func (lc *wifiLifecycle) handleSSIDChange(_, newSSID string) {
	rules, err := lc.store.Load()
	if err != nil {
		slog.Warn("wifi: rules reload failed, skipping action", "error", err)
		return
	}
	action, tunnelName := rules.Action(newSSID)
	slog.Info("wifi: SSID change action", "ssid", newSSID, "action", action, "tunnel", tunnelName)

	switch action {
	case "disconnect":
		lc.disconnectAll()
	case "connect":
		lc.connectTunnel(tunnelName)
	case "none":
		// Nothing to do
	}
}

// connectTunnel asks the helper to bring up the named tunnel, dispatching by
// protocol via tunnelService.Connect (WireGuard or OpenVPN — previously this
// loaded only the .conf path directly, so mapping an SSID to an OpenVPN
// tunnel silently did nothing). If any OTHER tunnel is already active we
// tear all of them down first — running extra tunnels just because the user
// moved between SSIDs is rarely what they want.
func (lc *wifiLifecycle) connectTunnel(name string) {
	active, err := lc.tunnelService.ActiveTunnelNames()
	if err != nil {
		slog.Warn("wifi: cannot query active tunnels — helper may be unavailable", "tunnel", name, "error", err)
		return
	}
	for _, n := range active {
		if n == name {
			continue
		}
		if err := lc.tunnelService.DisconnectTunnel(n); err != nil {
			slog.Warn("wifi: failed to disconnect other active tunnel before auto-connect", "tunnel", n, "error", err)
		}
	}

	if err := lc.tunnelService.Connect(name); err != nil {
		slog.Warn("wifi: connect failed", "tunnel", name, "error", err)
		return
	}
	slog.Info("wifi: auto-connected", "tunnel", name)
}

// disconnectAll tears down every currently active tunnel (WireGuard AND
// OpenVPN — previously this issued a single nameless Disconnect, which the
// helper resolves to only the FIRST active tunnel, silently leaving any
// others running and mis-recording their history sessions as closed).
func (lc *wifiLifecycle) disconnectAll() {
	active, err := lc.tunnelService.ActiveTunnelNames()
	if err != nil {
		slog.Warn("wifi: cannot query active tunnels for auto-disconnect", "error", err)
		return
	}
	for _, name := range active {
		if err := lc.tunnelService.DisconnectTunnel(name); err != nil {
			slog.Warn("wifi: auto-disconnect failed", "tunnel", name, "error", err)
			continue
		}
		slog.Info("wifi: auto-disconnected (trusted SSID)", "tunnel", name)
	}
}
