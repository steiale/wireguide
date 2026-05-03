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
	"context"
	"log/slog"
	"sync"
	"time"

	wgapp "github.com/steiale/wireguide/internal/app"
	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/storage"
	"github.com/steiale/wireguide/internal/wifi"
)

// wifiLifecycle owns the live wifi.Monitor and applies rule changes.
type wifiLifecycle struct {
	mu      sync.Mutex
	monitor *wifi.Monitor
	clients *ipc.ClientHolder
	store   *storage.WifiRulesStore
}

// startWifiLifecycle loads persisted rules, starts the monitor, and registers
// the rules-change hook so SaveWifiRules updates the live monitor in place.
// Returns the lifecycle so the caller can stop it on shutdown.
func startWifiLifecycle(clients *ipc.ClientHolder, store *storage.WifiRulesStore, tunnelStore *storage.TunnelStore) *wifiLifecycle {
	lc := &wifiLifecycle{clients: clients, store: store}

	rules, err := store.Load()
	if err != nil {
		slog.Warn("wifi rules: load failed, starting with defaults", "error", err)
		rules = wifi.DefaultRules()
	}

	lc.monitor = wifi.NewMonitor(rules, func(oldSSID, newSSID string) {
		lc.handleSSIDChange(oldSSID, newSSID, tunnelStore)
	})
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
func (lc *wifiLifecycle) handleSSIDChange(_, newSSID string, tunnelStore *storage.TunnelStore) {
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
		lc.connectTunnel(tunnelName, tunnelStore)
	case "none":
		// Nothing to do
	}
}

// connectTunnel asks the helper to bring up the named tunnel. If a different
// tunnel is already active we tear it down first — running two tunnels just
// because the user moved between SSIDs is rarely what they want, and the
// helper's connect path doesn't multiplex implicitly.
func (lc *wifiLifecycle) connectTunnel(name string, tunnelStore *storage.TunnelStore) {
	c := lc.clients.Get()
	if c == nil {
		slog.Warn("wifi: cannot connect — helper unavailable", "tunnel", name)
		return
	}
	cfg, err := tunnelStore.Load(name)
	if err != nil {
		slog.Warn("wifi: cannot load tunnel config", "tunnel", name, "error", err)
		return
	}
	meta, _ := tunnelStore.LoadMeta(name)
	autoReconnect := meta != nil && meta.AutoReconnect

	// If something else is active, disconnect it first. Use a short
	// timeout — if the helper is wedged we don't want to block the
	// poll goroutine indefinitely.
	var active ipc.StringResponse
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := c.CallWithContext(pingCtx, ipc.MethodActiveName, nil, &active); err == nil && active.Value != "" && active.Value != name {
		dcCtx, dcCancel := context.WithTimeout(context.Background(), 60*time.Second)
		_ = c.CallWithContext(dcCtx, ipc.MethodDisconnect, nil, nil)
		dcCancel()
	}
	cancel()

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer connectCancel()
	if err := c.CallWithContext(connectCtx, ipc.MethodConnect, ipc.ConnectRequest{
		Config:        cfg,
		AutoReconnect: autoReconnect,
	}, nil); err != nil {
		slog.Warn("wifi: connect failed", "tunnel", name, "error", err)
		return
	}
	slog.Info("wifi: auto-connected", "tunnel", name)
}

// disconnectAll tears down whatever the helper currently has up. We don't
// distinguish "no tunnel was active" from "helper unreachable" here — both
// cases just log and move on.
func (lc *wifiLifecycle) disconnectAll() {
	c := lc.clients.Get()
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.CallWithContext(ctx, ipc.MethodDisconnect, nil, nil); err != nil {
		slog.Warn("wifi: auto-disconnect failed", "error", err)
		return
	}
	slog.Info("wifi: auto-disconnected (trusted SSID)")
}
