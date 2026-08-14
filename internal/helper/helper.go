// Package helper implements the privileged helper process.
// Runs as root/admin, accepts RPC calls from the GUI, manages tunnel + firewall.
//
// The package is split across three files:
//   - helper.go   (this file) — Helper struct + Run() lifecycle
//   - handlers.go — RPC method handlers
//   - events.go   — status diff + broadcast loop, status conversion
package helper

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/firewall"
	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/ovpn"
	"github.com/steiale/wireguide/internal/reconnect"
	"github.com/steiale/wireguide/internal/tunnel"
)

// goSafe runs fn in a goroutine with panic recovery. Without this, a panic
// in ANY helper goroutine crashes the whole process — which is exactly what
// we've been unable to diagnose because the helper dies silently with no log
// trail. Every background goroutine in the helper should be started via this
// wrapper so panics are captured, logged, and surfaced instead of vanishing.
// goSafe runs fn in a goroutine with panic recovery and automatic restart.
// If fn panics, the panic is logged and fn is restarted after a 1-second
// backoff, up to maxRestarts times. This ensures critical background loops
// (like the event broadcast loop) survive transient panics instead of dying
// permanently. If fn returns normally (no panic), it is NOT restarted.
func goSafe(name string, fn func()) {
	const maxRestarts = 5
	go func() {
		for attempt := 0; attempt <= maxRestarts; attempt++ {
			panicked := true
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("goroutine panic (will restart)",
							"where", name,
							"panic", fmt.Sprintf("%v", r),
							"stack", string(debug.Stack()),
							"attempt", attempt+1,
							"max", maxRestarts+1)
					}
				}()
				fn()
				panicked = false
			}()
			if !panicked {
				return // fn returned normally — done.
			}
			// Backoff before restart to avoid tight panic loops.
			time.Sleep(1 * time.Second)
		}
		slog.Error("goroutine exceeded max restarts, giving up", "where", name)
	}()
}

// shutdownGrace is the window the helper waits after a GUI disconnect before
// terminating itself. Short enough to prevent orphan processes, long enough to
// tolerate a normal GUI restart.
const shutdownGrace = 10 * time.Second

// Helper holds the helper process state.
type Helper struct {
	server      *ipc.Server
	manager     *tunnel.Manager
	ovpnManager *ovpn.Manager
	firewall    firewall.FirewallManager
	monitor     *reconnect.Monitor

	// connectMu serializes Connect/Disconnect calls. Without this, two
	// concurrent GUI connections could race on activeCfg, with the loser's
	// rollback overwriting the winner's config.
	connectMu sync.Mutex

	// logLevel is the runtime-mutable slog level. Helper.SetLogLevel (and
	// the Settings UI) writes to this; the broadcast handler reads it for
	// every record. Info by default.
	logLevel *slog.LevelVar

	mu             sync.Mutex
	activeCfgs     map[string]*domain.WireGuardConfig // cached for reconnect, keyed by tunnel name
	activeOVPNCfgs map[string][]byte                  // raw .ovpn content cached for reconnect, keyed by tunnel name
	autoReconnect  map[string]bool                    // whether each connected tunnel should auto-reconnect (shared by both protocols)

	// Firewall state saved during reconnect suspend/resume cycle.
	// These track what was active before suspend so resume can restore it.
	fwSavedKillSwitch    bool
	fwSavedDNSProtection bool
	fwSavedDNSServers    []string // DNS servers to re-enable on resume
	// fwSuspendedTunnels is the set of tunnel names (retry sequences)
	// currently holding a firewall suspend — non-empty from the first
	// suspendFirewall() call across ALL concurrently-reconnecting tunnels
	// until every one of them has released via resumeFirewall(). A single
	// shared bool here previously meant tunnel A's resume would prematurely
	// clear the suspend (and restore/re-arm the firewall) while tunnel B
	// was still mid-reconnect, and — separately — meant a second
	// suspendFirewall() call within ONE tunnel's own retry sequence (a
	// failed attempt calls suspend again before the next retry) would
	// re-snapshot IsKillSwitchEnabled() — already false from the FIRST
	// suspend — permanently forgetting that the kill switch was ever on.
	// Tracking membership by tunnel name fixes both: only the transition
	// from empty to non-empty snapshots/disables, and only the transition
	// back to empty (every holder released) actually restores. See
	// resumeFirewall for the release-and-check-if-last-out side of this.
	fwSuspendedTunnels map[string]bool

	// fwRestoring is true for the (last-holder) duration of a resumeFirewall
	// call, from the moment it decides "I'm the last one out" to the moment
	// its restore attempt finishes (success or not). Without this, a BRAND
	// NEW tunnel's suspendFirewall call landing in that narrow window would
	// see fwSuspendedTunnels already empty (firstActivation==true) and
	// snapshot the CURRENTLY-still-disabled firewall state as if it were
	// the true original — the restore that was already in flight hasn't
	// actually re-armed anything yet. Checked alongside
	// len(fwSuspendedTunnels)==0 in suspendFirewall's firstActivation gate.
	fwRestoring bool

	// shutdownTimer is a singleton grace-window timer. When the control
	// connection drops we Reset it; when the GUI reconnects we Stop it. This
	// avoids the previous bug where every disconnect spawned a fresh goroutine
	// and multiple shutdowns could race.
	shutdownTimer *time.Timer

	done        chan struct{}
	cleanupOnce sync.Once
}

// Run starts the helper listening on addr. Blocks until shutdown.
// ownerUID: UID to chown socket to (Unix only, use -1 on Windows).
// dataDir: persistent data dir for crash recovery state.
func Run(addr string, ownerUID int, dataDir string) error {
	listener, err := ipc.Listen(addr, ownerUID)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	manager := tunnel.NewManager(dataDir)
	fw := firewall.NewPlatformFirewall()

	h := &Helper{
		server:         ipc.NewServer(listener, ownerUID),
		manager:        manager,
		firewall:       fw,
		activeCfgs:     make(map[string]*domain.WireGuardConfig),
		activeOVPNCfgs: make(map[string][]byte),
		autoReconnect:  make(map[string]bool),
		logLevel:       new(slog.LevelVar), // defaults to Info
		done:           make(chan struct{}),
	}

	// Install the broadcast slog handler BEFORE the first log call so
	// everything that follows (crash recovery notices, manager init,
	// handler registration) gets piped to subscribed GUIs.
	slog.SetDefault(slog.New(newBroadcastHandler(h.logLevel, func() func(string, interface{}) {
		if h.server == nil {
			return nil
		}
		return h.server.Broadcast
	})))

	// OpenVPN manager: resolve the bundled openvpn binary. Primary location is
	// next to the helper in /Library/PrivilegedHelperTools/ (copied there by the
	// install script). If that's missing — e.g. the helper version matched on
	// first launch so the install script never ran — fall back to the standard
	// app bundle location so openvpn works without a forced helper reinstall.
	ovpnBinary := filepath.Join(filepath.Dir(os.Args[0]), "openvpn")
	if _, err := os.Stat(ovpnBinary); err != nil {
		const appBundleFallback = "/Applications/LockPlus.app/Contents/MacOS/openvpn"
		if _, err2 := os.Stat(appBundleFallback); err2 == nil {
			slog.Info("openvpn not found next to helper, using app bundle fallback", "path", appBundleFallback)
			ovpnBinary = appBundleFallback
		}
	}
	ovpnRuntimeDir := filepath.Join(dataDir, "ovpn-run")
	h.ovpnManager = ovpn.NewManager(ovpnBinary, ovpnRuntimeDir,
		h.broadcastOvpnStatus,
		h.broadcastAuthPrompt,
		h.refreshKillSwitchForOVPNChange,
	)

	// Crash recovery (now logs via broadcast handler)
	if recovered := tunnel.RecoverFromCrash(dataDir); len(recovered) > 0 {
		slog.Warn("recovered from previous crash", "tunnels", recovered)
	}

	// Reconnect monitor — uses cached config
	h.monitor = reconnect.NewMonitor(manager, h.reconnectFn, h.onReconnectState, reconnect.DefaultConfig())
	h.monitor.SetFirewallCallbacks(h.suspendFirewall, h.resumeFirewall)
	h.monitor.SetShouldReconnect(func(name string) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.autoReconnect[name]
	})
	h.monitor.Start()
	// Wire engine/process self-death (wireguard-go tearing itself down after
	// a fatal TUN error, or an openvpn subprocess crashing/wedging — either
	// leaving the tunnel dead but still showing "Connected") into the same
	// reconnect path as a stale handshake or wake event.
	manager.SetOnEngineDied(h.onWireGuardEngineDied)
	if h.ovpnManager != nil {
		h.ovpnManager.SetOnDied(h.onOVPNDied)
	}

	// Register RPC handlers
	h.registerHandlers()

	// Grace-window shutdown on GUI disconnect — only when NOT running as a
	// LaunchDaemon. When the daemon plist has KeepAlive=true, launchd
	// handles restarts; the helper should stay alive even when no GUI is
	// connected (so the next GUI launch connects instantly without a
	// password prompt). In osascript/dev mode, the helper still shuts down
	// after the grace window to avoid orphan processes.
	if !isDaemon() {
		h.server.OnConnect(h.cancelShutdownTimer)
		h.server.OnDisconnect(h.startShutdownTimer)
	} else {
		slog.Info("running as LaunchDaemon — shutdown grace disabled")
	}

	// Start event emitter (diff loop)
	goSafe("eventLoop", h.eventLoop)

	// Top-level panic recovery for the Serve loop itself. If Accept or any
	// per-conn handler panics unrecovered, we at least want a stack trace.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("helper Run panic",
				"panic", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()))
		}
	}()

	slog.Info("helper listening", "addr", addr, "pid", "daemon")

	// Serve (blocks until shutdown)
	err = h.server.Serve()
	h.cleanup()
	return err
}

// reconnectFn is the callback passed to reconnect.Monitor. When name is
// non-empty, it reconnects only that specific tunnel. When name is empty
// (legacy sleep/wake path), it reconnects all cached tunnels.
// The connectMu is held during Connect to prevent races with concurrent
// GUI connect/disconnect calls.
func (h *Helper) reconnectFn(name string) error {
	h.mu.Lock()
	cfgs := h.copyActiveCfgs()
	ovpnContent, hasOVPN := h.activeOVPNCfgs[name]
	h.mu.Unlock()

	if name != "" {
		if cfg, ok := cfgs[name]; ok {
			h.connectMu.Lock()
			err := h.manager.Connect(cfg)
			h.connectMu.Unlock()
			return err
		}
		if hasOVPN && h.ovpnManager != nil {
			return h.reconnectOVPN(name, ovpnContent)
		}
		return fmt.Errorf("no cached config for tunnel %q", name)
	}

	// Legacy path: reconnect all tunnels.
	if len(cfgs) == 0 {
		return fmt.Errorf("no cached config for reconnect")
	}
	var lastErr error
	for _, cfg := range cfgs {
		h.connectMu.Lock()
		err := h.manager.Connect(cfg)
		h.connectMu.Unlock()
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// reconnectOVPN starts an OpenVPN tunnel and blocks until it actually
// reaches CONNECTED, unlike ovpn.Manager.Connect itself which returns as
// soon as the subprocess starts (auth prompts, TLS handshake, and TCP
// connect all happen asynchronously afterward). The reconnect monitor
// treats a nil reconnectFn error as "fully reconnected" and immediately
// tries to resume the kill switch using the new interface/remote
// (reconnect.Monitor.reconnectWithBackoff) — if that ran while OpenVPN was
// still mid-handshake, resumeFirewall would find no known interface yet,
// silently fail, and nothing would ever retry it, leaving the kill switch
// permanently disabled after every OpenVPN auto-reconnect. WireGuard
// doesn't need this wrapper because tunnel.Manager.Connect is already
// synchronous — it doesn't return until the interface is fully up.
func (h *Helper) reconnectOVPN(name string, ovpnContent []byte) error {
	h.connectMu.Lock()
	err := h.ovpnManager.Connect(name, ovpnContent)
	h.connectMu.Unlock()
	if err != nil {
		return err
	}

	// Bounded by roughly openvpn's own default --connect-timeout (120s)
	// with some margin, so a normal in-progress attempt (TCP connect, DNS
	// retry, auth prompt) isn't torn down while it still has a real chance
	// to succeed. Pushed forward for as long as the tunnel is genuinely
	// waiting on the USER, not stuck — onMgmtAuthPrompt's own timeout is 10
	// minutes, and a 2FA/password profile needs live typing on every
	// auto-reconnect (the frontend deliberately never pre-fills the
	// password). Without this, a slow-to-type user would get their
	// in-progress auth modal yanked out from under them every 90s,
	// indefinitely, by this very timeout tearing down the process it's
	// talking to.
	const connectTimeout = 90 * time.Second
	deadline := time.Now().Add(connectTimeout)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-h.done:
			// Helper is shutting down (cleanup() closes this before
			// monitor.Stop()/firewall.Cleanup() run) — stop polling well
			// before those run, instead of racing a resume against
			// firewall.Cleanup() for up to this function's full timeout.
			return fmt.Errorf("openvpn tunnel %q: helper shutting down", name)
		case <-ticker.C:
		}
		status := h.ovpnManager.GetStatus(name)
		if status == nil {
			return fmt.Errorf("openvpn tunnel %q disappeared while connecting", name)
		}
		switch status.State {
		case domain.StateConnected:
			// StateConnected alone isn't quite enough: the kill switch's
			// resume (what this whole wrapper exists to make safe) needs
			// ActiveRemotes to actually include this tunnel — which also
			// requires remoteAddr and InterfaceName to be populated. Both
			// normally land at/near the same CONNECTED transition, but
			// remoteAddr's STATE fields are documented as optional and
			// InterfaceName is set from an independent stdout-scanning
			// goroutine — so wait the extra beat rather than assume.
			if ovpnTunnelHasKnownRemote(h.ovpnManager, name) {
				return nil
			}
		case domain.StateError, domain.StateDisconnected:
			return fmt.Errorf("openvpn tunnel %q failed to connect: %s", name, status.ErrorMessage)
		}
		if h.ovpnManager.IsAwaitingCredentials(name) {
			deadline = time.Now().Add(connectTimeout)
		}
	}
	// Still not connected after the bound: disconnect the in-flight attempt
	// rather than leaving it running — otherwise the NEXT retry's Connect()
	// call would immediately fail with "already active" against a process
	// that might now be stuck forever, and no attempt would ever get a
	// clean restart.
	_ = h.ovpnManager.Disconnect(name)
	return fmt.Errorf("openvpn tunnel %q did not connect within %s", name, connectTimeout)
}

// ovpnTunnelHasKnownRemote reports whether name appears in the OpenVPN
// manager's ActiveRemotes — i.e. it's not just CONNECTED but has a known
// remote address and interface name, the specific fields the kill switch's
// resume needs. See reconnectOVPN's StateConnected case for why this extra
// check exists.
func ovpnTunnelHasKnownRemote(m *ovpn.Manager, name string) bool {
	for _, r := range m.ActiveRemotes() {
		if r.TunnelName == name {
			return true
		}
	}
	return false
}

// onWireGuardEngineDied is invoked by tunnel.Manager (via SetOnEngineDied)
// after it has torn down a WireGuard tunnel whose engine died on its own —
// see Engine.Died's doc comment — rather than via a user-initiated
// Disconnect. tunnel.Manager only handles its own routes/DNS/state; this
// closure runs the equivalent of handleDisconnect's HELPER-level cleanup
// (cached config, auto-reconnect flag, kill switch) before deciding whether
// to reconnect, so a dead tunnel with auto-reconnect disabled doesn't leave
// stale tracking state or a kill-switch ruleset pointing at a peer/interface
// that no longer exists.
func (h *Helper) onWireGuardEngineDied(name string) {
	h.mu.Lock()
	shouldReconnect := h.autoReconnect[name]
	if !shouldReconnect {
		delete(h.activeCfgs, name)
		delete(h.autoReconnect, name)
	}
	h.mu.Unlock()
	h.refreshKillSwitchIfEnabled("wg-engine-died", name)
	h.monitor.NotifyTunnelDied(name)
}

// onOVPNDied is the OpenVPN analog of onWireGuardEngineDied, invoked by
// ovpn.Manager (via SetOnDied) after a connected tunnel's openvpn subprocess
// died on its own (crashed, or its management socket went silent for 30s —
// see management.go's read deadline) rather than via a user-initiated
// Disconnect. The kill switch is already refreshed by ovpn.Manager's
// existing onActiveChange callback before this runs, so only the cached
// config / auto-reconnect tracking needs handling here.
func (h *Helper) onOVPNDied(name string) {
	h.mu.Lock()
	shouldReconnect := h.autoReconnect[name]
	if !shouldReconnect {
		delete(h.activeOVPNCfgs, name)
		delete(h.autoReconnect, name)
	}
	h.mu.Unlock()
	h.monitor.NotifyTunnelDied(name)
}

// copyActiveCfgs returns a shallow copy of the active configs map.
// Caller MUST hold h.mu.
func (h *Helper) copyActiveCfgs() map[string]*domain.WireGuardConfig {
	cp := make(map[string]*domain.WireGuardConfig, len(h.activeCfgs))
	for k, v := range h.activeCfgs {
		cp[k] = v
	}
	return cp
}

// broadcastOvpnStatus is the onStatus callback for the OpenVPN manager. It
// pushes an EventStatus carrying the merged status so the GUI updates the same
// way it does for WireGuard. The eventLoop's diff is WireGuard-only, so OpenVPN
// state changes are broadcast here directly (the event is idempotent on the
// GUI side).
func (h *Helper) broadcastOvpnStatus(status domain.ConnectionStatus) {
	if h.server == nil {
		return
	}
	h.server.Broadcast(ipc.EventStatus, h.statusDTO())
}

// broadcastAuthPrompt notifies the GUI that an OpenVPN tunnel is waiting for
// credentials (e.g. a TOTP code) — or, if challenge is non-nil, a
// challenge/response answer (see ovpn.AuthChallenge).
func (h *Helper) broadcastAuthPrompt(tunnelName string, challenge *ovpn.AuthChallenge) {
	if h.server == nil {
		return
	}
	payload := ipc.AuthPromptEventPayload{TunnelName: tunnelName}
	if challenge != nil {
		payload.ChallengeKind = string(challenge.Kind)
		payload.ChallengeText = challenge.Text
		payload.ChallengeEcho = challenge.Echo
		payload.ChallengeConcat = challenge.Concat
	}
	h.server.Broadcast(ipc.EventAuthPrompt, payload)
}

// refreshKillSwitchForOVPNChange is the OpenVPN manager's onActiveChange
// callback (see ovpn.Manager) — fired when an OpenVPN tunnel reaches
// CONNECTED or is torn down.
func (h *Helper) refreshKillSwitchForOVPNChange(tunnelName string, active bool) {
	ctx := "ovpn-disconnect"
	if active {
		ctx = "ovpn-connect"
	}
	h.refreshKillSwitchIfEnabled(ctx, tunnelName)
}

// refreshKillSwitchIfEnabled rebuilds the kill switch's pf ruleset from the
// CURRENT set of active tunnels, if the kill switch is currently enabled.
// Its ruleset was built from whatever tunnels were active at the time it
// was last (re)loaded and does NOT automatically pick up tunnels that
// connect/disconnect afterward — see EnableKillSwitch's doc comment. Called
// as a best-effort side effect after any WireGuard or OpenVPN
// connect/disconnect that already succeeded (or is already being torn
// down), so failures here are logged, not propagated — the connect/
// disconnect the caller actually asked for should not be affected by
// whether the kill switch happens to pick it up immediately.
func (h *Helper) refreshKillSwitchIfEnabled(context, tunnelName string) {
	if !h.firewall.IsKillSwitchEnabled() {
		return
	}
	if err := h.enableKillSwitchNow(); err != nil {
		// E.g. the newly-connected tunnel's remote couldn't be resolved, or
		// nothing is active anymore — the existing (possibly now-stale)
		// ruleset stays loaded rather than risk disabling the kill switch
		// outright.
		slog.Warn("refreshKillSwitchIfEnabled: failed to rebuild kill switch",
			"context", context, "tunnel", tunnelName, "error", err)
	}
}

// enableKillSwitchNow builds and loads the kill switch pf ruleset from the
// CURRENT set of active tunnels (WireGuard + OpenVPN). Shared by the manual
// toggle (handleSetKillSwitch) and the OpenVPN connect/disconnect refresh
// above, so both compute the exact same ruleset the same way.
func (h *Helper) enableKillSwitchNow() error {
	status := h.manager.Status()
	wgConnected := status.State == tunnel.StateConnected

	// OpenVPN tunnels whose remote was successfully resolved (see
	// ovpn.Manager.ActiveRemotes) get their own pass-rule too.
	extra := h.killSwitchExtraTunnels()

	if !wgConnected && len(extra) == 0 {
		// Distinguish "an OpenVPN tunnel is active but its remote
		// couldn't be resolved/whitelisted" (rare: DNS failed at Connect
		// time) from "nothing active at all" for a clearer error.
		if h.ovpnManager != nil {
			for _, ovpnStatus := range h.ovpnManager.AllStatuses() {
				if ovpnStatus.State == domain.StateConnected {
					return fmt.Errorf("kill switch cannot whitelist this OpenVPN tunnel (its remote could not be resolved) — try reconnecting")
				}
			}
		}
		return fmt.Errorf("no active tunnel")
	}

	var endpoints []string
	var ifaceAddresses []string
	ifaceName := ""
	if wgConnected {
		ifaceName = status.InterfaceName
		// Use pre-resolved endpoints (resolved before tunnel routes were
		// installed). Doing DNS resolution here would fail because the
		// kill switch is about to block non-tunnel traffic and/or the
		// query would route through the tunnel itself.
		endpoints = h.manager.ResolvedEndpoints()
		if len(endpoints) == 0 {
			return fmt.Errorf("no resolved endpoints available — tunnel may have disconnected")
		}
		// Get interface addresses from ALL active configs for anti-spoof
		// chains. With multiple tunnels, the kill switch must allow
		// traffic from every tunnel's interface addresses, not just the
		// first one.
		h.mu.Lock()
		for _, cfg := range h.activeCfgs {
			ifaceAddresses = append(ifaceAddresses, cfg.Interface.Address...)
		}
		h.mu.Unlock()
	}

	return h.firewall.EnableKillSwitch(ifaceName, ifaceAddresses, endpoints, extra)
}

// onReconnectState forwards reconnection state changes to any subscribed GUI.
func (h *Helper) onReconnectState(state reconnect.State) {
	h.server.Broadcast(ipc.EventReconnect, ipc.ReconnectStateDTO{
		Reconnecting: state.Reconnecting,
		Attempt:      state.Attempt,
		MaxAttempts:  state.MaxAttempts,
		NextRetry:    state.NextRetry,
	})
}

// anyTunnelActive reports whether any WireGuard or OpenVPN tunnel is
// currently active. Used by the shutdown-grace-timer logic, which must
// consider both protocols — checking WireGuard alone would tear down a live
// OpenVPN-only session if the GUI process dies (crash/kill; a clean quit
// disconnects everything first) during the grace window.
func (h *Helper) anyTunnelActive() (name string, active bool) {
	if h.manager != nil {
		if t := h.manager.ActiveTunnel(); t != "" {
			return t, true
		}
	}
	if h.ovpnManager != nil {
		if names := h.ovpnManager.ActiveTunnelNames(); len(names) > 0 {
			return names[0], true
		}
	}
	return "", false
}

// startShutdownTimer begins (or re-begins) the grace-window countdown. Called
// when the GUI's control connection drops.
//
// CRITICAL DESIGN: wg-quick never shuts down while a tunnel is active. Our
// helper must follow the same principle. If a tunnel is connected, we do NOT
// start the shutdown timer — the helper stays alive indefinitely, just like
// wg-quick's monitor_daemon. The timer only applies when there is no active
// tunnel (i.e., the user disconnected and then closed the GUI).
func (h *Helper) startShutdownTimer() {
	active, isActive := h.anyTunnelActive()

	if isActive {
		slog.Info("GUI disconnected but tunnel is active — helper stays alive (wg-quick semantics)",
			"active_tunnel", active)
		return
	}

	slog.Info("GUI disconnected, no active tunnel — starting shutdown grace window",
		"grace", shutdownGrace)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.shutdownTimer != nil {
		h.shutdownTimer.Stop()
	}
	h.shutdownTimer = time.AfterFunc(shutdownGrace, func() {
		// Double-check at fire time: a tunnel may have been activated between
		// timer start and fire (e.g., reconnect monitor brought it back up).
		if t, ok := h.anyTunnelActive(); ok {
			slog.Info("shutdown timer fired but tunnel is now active — aborting shutdown",
				"active_tunnel", t)
			return
		}
		slog.Info("no reconnect within grace window, shutting down")
		h.shutdown()
	})
}

// cancelShutdownTimer aborts a pending grace-window shutdown. Called when the
// GUI reconnects before the timer fires.
func (h *Helper) cancelShutdownTimer() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.shutdownTimer != nil {
		if h.shutdownTimer.Stop() {
			slog.Info("GUI reconnected within grace window, shutdown cancelled")
		}
		h.shutdownTimer = nil
	}
}

func (h *Helper) shutdown() {
	h.server.Shutdown()
}

// isDaemon returns true when the helper was started by launchd (LaunchDaemon).
// launchd always sets the process's parent PID to 1 (init/launchd).
func isDaemon() bool {
	return os.Getppid() == 1
}

// killSwitchExtraTunnels builds the kill switch's "additional tunnels" list
// (currently just OpenVPN) from every connected OVPN tunnel whose remote was
// successfully resolved — see ovpn.Manager.ActiveRemotes. Shared by
// handleSetKillSwitch (manual toggle) and resumeFirewall (post-reconnect
// restore) so both paths whitelist OpenVPN identically.
func (h *Helper) killSwitchExtraTunnels() []firewall.KillSwitchTunnel {
	if h.ovpnManager == nil {
		return nil
	}
	var extra []firewall.KillSwitchTunnel
	for _, r := range h.ovpnManager.ActiveRemotes() {
		extra = append(extra, firewall.KillSwitchTunnel{
			InterfaceName: r.InterfaceName,
			Proto:         r.Proto,
			Endpoints:     []string{r.Addr},
		})
	}
	return extra
}

// clearFirewallSuspendState discards any in-progress reconnect suspend/resume
// bookkeeping. Called before a MANUAL kill-switch/DNS-protection toggle
// (handleSetKillSwitch/handleSetDNSProtection): a cancelled or abandoned
// reconnect retry sequence can leave fwSuspended stuck true (see
// suspendFirewall/resumeFirewall) until a later resumeFirewall call happens
// to complete — during that window, a user's own explicit toggle should win
// outright, not risk being silently overridden by a stale saved value once
// some later, unrelated resume eventually fires.
func (h *Helper) clearFirewallSuspendState() {
	h.mu.Lock()
	h.fwSuspendedTunnels = nil
	h.fwSavedKillSwitch = false
	h.fwSavedDNSProtection = false
	h.fwSavedDNSServers = nil
	h.mu.Unlock()
}

// suspendFirewall saves the current firewall state and disables all firewall
// rules. Called by the reconnect monitor before Disconnect so that old pf rules
// referencing the previous utun interface name don't block the new connection.
// tunnelName identifies the calling retry sequence — see fwSuspendedTunnels.
func (h *Helper) suspendFirewall(tunnelName string) error {
	h.mu.Lock()
	if h.fwSuspendedTunnels == nil {
		h.fwSuspendedTunnels = make(map[string]bool)
	}
	// See fwRestoring's doc comment: a resume in flight for the last
	// previous holder counts as "not first activation" too, even though
	// the set is momentarily empty during that window.
	firstActivation := len(h.fwSuspendedTunnels) == 0 && !h.fwRestoring
	h.fwSuspendedTunnels[tunnelName] = true
	h.mu.Unlock()
	if !firstActivation {
		// Either this same tunnel's own earlier attempt in this retry
		// sequence never got a chance to resume successfully (failed
		// attempt, or the new interface wasn't ready yet — see
		// resumeFirewall), or a DIFFERENT tunnel's retry sequence already
		// holds the suspend. Either way the firewall is already down, so
		// re-reading IsKillSwitchEnabled()/IsDNSProtectionEnabled() now
		// would capture "false" (the CURRENT, suspended state) instead of
		// the TRUE original state we still need to restore — permanently
		// losing it. fwSaved* already holds the real original values from
		// whichever call first activated the suspend; leave them alone.
		slog.Debug("suspendFirewall: already suspended (this or another tunnel's retry sequence), not re-snapshotting", "tunnel", tunnelName)
		return nil
	}

	ksEnabled := h.firewall.IsKillSwitchEnabled()
	dnsEnabled := h.firewall.IsDNSProtectionEnabled()

	h.mu.Lock()
	h.fwSavedKillSwitch = ksEnabled
	h.fwSavedDNSProtection = dnsEnabled
	// H2: Union DNS lists from ALL active configs (not just the first one
	// with a non-empty DNS list). With multi-tunnel setups, breaking on the
	// first match silently dropped DNS servers belonging to other tunnels
	// when the firewall was resumed. This also includes OpenVPN tunnels'
	// server-pushed DNS — WireGuard-only snapshotting here meant a WG
	// tunnel's reconnect could resume DNS protection using only WG's static
	// DNS list (or none), silently discarding a concurrently active OVPN
	// tunnel's pushed DNS servers from the restored allowlist.
	seen := make(map[string]struct{})
	var combined []string
	for _, cfg := range h.activeCfgs {
		for _, dns := range cfg.Interface.DNS {
			if dns == "" {
				continue
			}
			if _, ok := seen[dns]; ok {
				continue
			}
			seen[dns] = struct{}{}
			combined = append(combined, dns)
		}
	}
	if h.ovpnManager != nil {
		for _, st := range h.ovpnManager.AllStatuses() {
			for _, dns := range st.DNSServers {
				if dns == "" {
					continue
				}
				if _, ok := seen[dns]; ok {
					continue
				}
				seen[dns] = struct{}{}
				combined = append(combined, dns)
			}
		}
	}
	h.fwSavedDNSServers = combined
	h.mu.Unlock()

	if !ksEnabled && !dnsEnabled {
		slog.Debug("suspendFirewall: no firewall rules active, nothing to suspend")
		return nil
	}

	slog.Info("suspending firewall rules for reconnect",
		"kill_switch", ksEnabled, "dns_protection", dnsEnabled)

	// Disable DNS protection first (it may be a sub-anchor of the kill switch).
	if dnsEnabled {
		if err := h.firewall.DisableDNSProtection(); err != nil {
			slog.Warn("suspendFirewall: failed to disable DNS protection", "error", err)
		}
	}
	if ksEnabled {
		if err := h.firewall.DisableKillSwitch(); err != nil {
			return fmt.Errorf("suspendFirewall: disable kill switch: %w", err)
		}
	}

	return nil
}

// resumeFirewall re-enables firewall rules that were active before the
// reconnect suspend. It reads the NEW interface name and endpoints from the
// tunnel manager so the pf rules match the newly created utun interface.
// tunnelName must match the value passed to the corresponding
// suspendFirewall call — see fwSuspendedTunnels.
func (h *Helper) resumeFirewall(tunnelName string) error {
	// Deliberately does NOT remove tunnelName from fwSuspendedTunnels until
	// we know this is the last (or only) holder, and even then not until
	// the restore actually completes (ksDone && dnsDone below). A reconnect
	// attempt that fails before the new interface exists (the common case:
	// suspend → disconnect → reconnect fails → resume, with no interface
	// yet) must keep this tunnel's membership so its NEXT suspendFirewall
	// call still sees firstActivation==false and doesn't re-snapshot the
	// CURRENTLY-disabled state as if it were the true original.
	h.mu.Lock()
	othersStillSuspended := false
	for name := range h.fwSuspendedTunnels {
		if name != tunnelName {
			othersStillSuspended = true
			break
		}
	}
	if othersStillSuspended {
		// Another tunnel's retry sequence still holds the suspend — the
		// firewall must stay down until every holder has released,
		// otherwise disconnecting/reconnecting tunnel A would prematurely
		// re-arm rules (referencing A's possibly-still-changing interface)
		// while tunnel B is still mid-reconnect and unprotected by them.
		//
		// Release THIS tunnel's own hold before returning — safe precisely
		// because othersStillSuspended==true guarantees the set stays
		// non-empty either way, so the anti-re-snapshot guard in
		// suspendFirewall (firstActivation) still holds for every
		// remaining holder. Not releasing it here (an earlier version of
		// this function didn't) meant a tunnel could never leave the set
		// once a second one joined: both A and B's eventual resume calls
		// would each see "the other is still in the set" and defer forever,
		// permanently disabling the kill switch/DNS protection with no
		// tunnel left to ever release it (short of a manual toggle).
		delete(h.fwSuspendedTunnels, tunnelName)
		h.mu.Unlock()
		slog.Debug("resumeFirewall: other tunnels still hold the suspend, deferring restore", "tunnel", tunnelName)
		return nil
	}
	// This tunnel is the last (or only) holder. Mark a restore as in
	// flight for the rest of this call — see fwRestoring's doc comment —
	// so a BRAND NEW tunnel's suspendFirewall call landing in the window
	// between here and the actual EnableKillSwitch/EnableDNSProtection
	// calls below doesn't see fwSuspendedTunnels as momentarily empty and
	// snapshot the still-disabled state as if it were the true original.
	h.fwRestoring = true
	restoreKS := h.fwSavedKillSwitch
	restoreDNS := h.fwSavedDNSProtection
	savedDNSServers := h.fwSavedDNSServers
	var ifaceAddresses []string
	for _, cfg := range h.activeCfgs {
		ifaceAddresses = append(ifaceAddresses, cfg.Interface.Address...)
	}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.fwRestoring = false
		h.mu.Unlock()
	}()

	if !restoreKS && !restoreDNS {
		// Nothing was ever actually suspended for this tunnel (or a
		// previous call already fully restored and cleared it) — release
		// this tunnel's membership, if any, since there's nothing left to
		// preserve it for.
		h.mu.Lock()
		delete(h.fwSuspendedTunnels, tunnelName)
		h.mu.Unlock()
		slog.Debug("resumeFirewall: no firewall rules to restore")
		return nil
	}

	status := h.manager.Status()
	ifaceName := ""
	if status != nil {
		ifaceName = status.InterfaceName
	}

	slog.Info("resuming firewall rules after reconnect",
		"kill_switch", restoreKS, "dns_protection", restoreDNS,
		"new_interface", ifaceName)

	// ksDone/dnsDone track whether each requested restore actually
	// happened. Unlike the previous version, fwSaved*/fwSuspended are only
	// cleared once everything that needed restoring has been restored —
	// otherwise a reconnect attempt that fails before the new interface
	// exists (the common case: suspend → disconnect → reconnect fails →
	// resume, with no interface yet) would permanently discard the "kill
	// switch was on" signal instead of preserving it for the next retry's
	// resume call.
	ksDone := true
	if restoreKS {
		ksDone = false
		// A WG reconnect's suspend/resume cycle must not drop a concurrently
		// active OpenVPN tunnel's kill-switch whitelist entry — include it
		// here the same way handleSetKillSwitch does for a manual toggle.
		extra := h.killSwitchExtraTunnels()
		if ifaceName == "" && len(extra) == 0 {
			slog.Warn("resumeFirewall: no interface available (WireGuard or OpenVPN), cannot re-enable kill switch yet")
		} else {
			var endpoints []string
			if ifaceName != "" {
				endpoints = h.manager.ResolvedEndpoints()
			}
			if ifaceName != "" && len(endpoints) == 0 {
				slog.Warn("resumeFirewall: no resolved endpoints, cannot re-enable kill switch yet")
			} else {
				if err := h.firewall.EnableKillSwitch(ifaceName, ifaceAddresses, endpoints, extra); err != nil {
					slog.Error("resumeFirewall: failed to re-enable kill switch", "error", err)
					return fmt.Errorf("resumeFirewall: enable kill switch: %w", err)
				}
				ksDone = true
			}
		}
	}

	dnsDone := true
	if restoreDNS {
		dnsDone = false
		if ifaceName == "" {
			slog.Warn("resumeFirewall: no interface name available, cannot re-enable DNS protection yet")
		} else if len(savedDNSServers) == 0 {
			slog.Warn("resumeFirewall: no DNS servers saved, cannot re-enable DNS protection")
			dnsDone = true // nothing we could ever restore here — don't retry forever
		} else {
			if err := h.firewall.EnableDNSProtection(ifaceName, savedDNSServers); err != nil {
				slog.Error("resumeFirewall: failed to re-enable DNS protection", "error", err)
				return fmt.Errorf("resumeFirewall: enable DNS protection: %w", err)
			}
			dnsDone = true
		}
	}

	if ksDone && dnsDone {
		h.mu.Lock()
		h.fwSavedKillSwitch = false
		h.fwSavedDNSProtection = false
		h.fwSavedDNSServers = nil
		delete(h.fwSuspendedTunnels, tunnelName)
		h.mu.Unlock()
	} else {
		slog.Debug("resumeFirewall: restore incomplete, keeping saved state for next attempt",
			"kill_switch_restored", ksDone, "dns_restored", dnsDone)
	}

	return nil
}

func (h *Helper) cleanup() {
	h.cleanupOnce.Do(func() {
		slog.Info("helper cleanup starting",
			"connected", h.manager.IsConnected(),
			"call_stack", string(debug.Stack()))
		close(h.done)
		h.mu.Lock()
		t := h.shutdownTimer
		h.shutdownTimer = nil
		h.mu.Unlock()
		if t != nil {
			t.Stop()
		}
		h.monitor.Stop()
		h.firewall.Cleanup()
		// Unconditional, not gated on IsConnected(): a tunnel still in
		// StateConnecting (not yet StateConnected) has already installed
		// routes/DNS by the time this runs concurrently with a slow
		// connect, but IsConnected() only reports true tunnels — gating on
		// it skipped teardown entirely for an in-flight connect, leaving
		// its DNS override in place with the process about to exit.
		// DisconnectAll already handles both states and is a no-op if
		// nothing is active.
		h.manager.DisconnectAll()
		if h.ovpnManager != nil {
			h.ovpnManager.Stop()
		}
		slog.Info("helper shutdown complete")
	})
}
