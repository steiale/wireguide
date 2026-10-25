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
	"slices"
	"sync"
	"time"

	wgapp "github.com/steiale/wireguide/internal/app"
	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/storage"
	"github.com/steiale/wireguide/internal/wifi"
)

// wifiLifecycle owns the live wifi.Monitor and applies rule changes.
type wifiLifecycle struct {
	mu            sync.Mutex
	monitor       *wifi.Monitor
	unsubAuth     func()
	tunnelService *wgapp.TunnelService
	store         *storage.WifiRulesStore
	gen           uint64 // bumped per Wi-Fi action and on stop (see releaseAfterConnected)
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

	// Reading the SSID needs Location Services authorization. Create the
	// long-lived CLLocationManager (main thread, never prompts) so a grant
	// made later in System Settings re-polls immediately — no restart. Only
	// prompt at launch when rules would actually use the SSID and the user
	// has never been asked; the prompt itself is dispatched to the main
	// queue and appears once the AppKit loop runs.
	mon := lc.monitor
	lc.unsubAuth = wifi.OnLocationAuthChange(func(st wifi.AuthStatus) {
		slog.Info("wifi: location authorization changed", "status", st)
		mon.Recheck()
	})
	wifi.StartLocationObserver()
	if rules.HasActiveRules() && wifi.LocationAuthStatus() == wifi.AuthNotDetermined {
		slog.Info("wifi: rules active and location not determined, requesting authorization")
		wifi.RequestLocationAuth()
	}

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
		// Prompting on rule add/enable is done by the Wi-Fi rules UI
		// (TunnelService.RequestLocationAuth) so it fires once, in context.
	})

	return lc
}

// stop halts the monitor goroutine. Idempotent.
func (lc *wifiLifecycle) stop() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.gen++ // ends a pending releaseAfterConnected
	if lc.monitor != nil {
		lc.monitor.Stop()
	}
	if lc.unsubAuth != nil {
		lc.unsubAuth()
		lc.unsubAuth = nil
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
	slog.Info("wifi: SSID change action", "ssid", wifi.SSIDTag(newSSID), "action", action, "tunnel", tunnelName)

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
// tunnel silently did nothing). Other tunnels are torn down — running extra
// tunnels just because the user moved between SSIDs is rarely what they
// want — but only RUNNING ones before the connect. A protected one
// (reconnecting, or blocked by the kill switch) is released only once the
// new tunnel reports connected: releasing a block first would drop the
// kill switch and leak until the new tunnel is up. The helper passes the
// new tunnel's endpoints through such a block while it connects. If the
// new tunnel never connects, the protected ones stay (fail closed).
func (lc *wifiLifecycle) connectTunnel(name string) {
	gen := lc.nextGen()
	running, protected, err := wgapp.RunningAndProtectedTunnels(lc.tunnelService)
	if err != nil {
		slog.Warn("wifi: cannot query active tunnels — helper may be unavailable", "tunnel", name, "error", err)
		return
	}
	for _, n := range running {
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

	var release []string
	for _, n := range protected {
		if n != name {
			release = append(release, n)
		}
	}
	if len(release) > 0 {
		go lc.releaseAfterConnected(gen, name, release)
	}
}

// wifiReleaseWait bounds how long releaseAfterConnected waits for the new
// tunnel (an OpenVPN connect may wait on a 2FA prompt).
const wifiReleaseWait = 3 * time.Minute

// releaseAfterConnected disconnects the protected tunnels in release once
// name reports connected, so their kill-switch block or hold only ends
// when the new tunnel protects the traffic. Gives up (leaving them) on
// timeout or when a newer Wi-Fi action superseded this one (gen).
func (lc *wifiLifecycle) releaseAfterConnected(gen uint64, name string, release []string) {
	deadline := time.Now().Add(wifiReleaseWait)
	for {
		if lc.currentGen() != gen {
			return
		}
		if st, err := lc.tunnelService.GetStatus(); err == nil && tunnelConnected(st, name) {
			break
		}
		if time.Now().After(deadline) {
			slog.Warn("wifi: auto-connected tunnel did not connect, other tunnels left protected", "tunnel", name, "kept", release)
			return
		}
		time.Sleep(time.Second)
	}
	running, protected, err := wgapp.RunningAndProtectedTunnels(lc.tunnelService)
	if err != nil || lc.currentGen() != gen {
		return
	}
	for _, n := range release {
		if !slices.Contains(running, n) && !slices.Contains(protected, n) {
			continue // already gone
		}
		if err := lc.tunnelService.DisconnectTunnel(n); err != nil {
			slog.Warn("wifi: failed to release other tunnel after auto-connect", "tunnel", n, "error", err)
		}
	}
}

// tunnelConnected reports whether st shows name connected.
func tunnelConnected(st *wgapp.ConnectionStatus, name string) bool {
	if st == nil {
		return false
	}
	if st.TunnelName == name && st.State == domain.StateConnected {
		return true
	}
	for _, t := range st.Tunnels {
		if t.TunnelName == name && t.State == domain.StateConnected {
			return true
		}
	}
	return false
}

// nextGen starts a new Wi-Fi action, superseding pending releases.
func (lc *wifiLifecycle) nextGen() uint64 {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.gen++
	return lc.gen
}

func (lc *wifiLifecycle) currentGen() uint64 {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.gen
}

// disconnectAll tears down every currently active tunnel (WireGuard AND
// OpenVPN — previously this issued a single nameless Disconnect, which the
// helper resolves to only the FIRST active tunnel, silently leaving any
// others running and mis-recording their history sessions as closed).
func (lc *wifiLifecycle) disconnectAll() {
	lc.nextGen()
	active, err := wgapp.ActiveTunnelNames(lc.tunnelService)
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
