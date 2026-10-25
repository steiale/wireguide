// Package helper implements the privileged helper process.
// Runs as root/admin, accepts RPC calls from the GUI, manages tunnel + firewall.
//
// The package is split across:
//   - helper.go   (this file) — Helper struct + Run() lifecycle, reconnect
//   - firewall.go — kill switch / DNS protection policy
//   - handlers.go — RPC method handlers
//   - events.go   — status diff + broadcast loop, status conversion
package helper

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/firewall"
	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/network"
	"github.com/steiale/wireguide/internal/ovpn"
	"github.com/steiale/wireguide/internal/reconnect"
	"github.com/steiale/wireguide/internal/tunnel"
)

// goSafe runs fn in a goroutine with panic recovery: a panic is logged and
// fn restarted after 1s, up to maxRestarts times, so background loops
// survive transient panics. A normal return is not restarted.
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
	ovpnBinary  string // root-owned openvpn path next to the helper binary
	firewall    firewall.FirewallManager
	monitor     *reconnect.Monitor

	// connectMu serializes connect, disconnect, reconnect and cleanup.
	connectMu sync.Mutex

	// logLevel is the runtime-mutable slog level (Helper.SetLogLevel).
	logLevel *slog.LevelVar

	// fwMu serializes applyFirewall (compute + load).
	fwMu sync.Mutex

	mu             sync.Mutex
	activeCfgs     map[string]*domain.WireGuardConfig // cached for reconnect, keyed by tunnel name
	activeOVPNCfgs map[string][]byte                  // raw .ovpn content cached for reconnect
	autoReconnect  map[string]bool                    // per-tunnel auto-reconnect (both protocols)
	policy         fwPolicy                           // desired firewall state, set by the GUI
	fwHeld         map[string]bool                    // tunnels in a reconnect sequence
	fwEndpoints    map[string]cachedEndpoints         // last known server endpoints per tunnel
	ovpnErrors     map[string]domain.ConnectionStatus // last StateError snapshot per OpenVPN tunnel

	// shutdownTimer is the grace-window timer: (re)started when the GUI's
	// control connection drops, stopped when it reconnects.
	shutdownTimer *time.Timer

	done        chan struct{}
	cleanupOnce sync.Once
}

// Run starts the helper listening on addr. Blocks until shutdown.
// ownerUID: UID to chown the socket to (-1 to skip).
// dataDir: persistent data dir for crash recovery state.
func Run(addr string, ownerUID int, dataDir string) error {
	// Bind first: Listen refuses to replace a live helper's socket, so a
	// second instance exits here before touching pf, DNS or routes.
	listener, err := ipc.Listen(addr, ownerUID)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	manager := tunnel.NewManager(dataDir)
	h := &Helper{
		server:         ipc.NewServer(listener, ownerUID),
		manager:        manager,
		firewall:       firewall.NewPlatformFirewall(),
		activeCfgs:     make(map[string]*domain.WireGuardConfig),
		activeOVPNCfgs: make(map[string][]byte),
		autoReconnect:  make(map[string]bool),
		fwHeld:         make(map[string]bool),
		fwEndpoints:    make(map[string]cachedEndpoints),
		ovpnErrors:     make(map[string]domain.ConnectionStatus),
		logLevel:       new(slog.LevelVar), // defaults to Info
		done:           make(chan struct{}),
	}
	// Pipe every log record (including recovery below) to subscribed GUIs.
	slog.SetDefault(slog.New(newBroadcastHandler(h.logLevel, h.server.Broadcast)))

	// Startup recovery from a previous helper that died without cleanup():
	// stale pf rules, orphaned routes, overridden DNS. Runs before Serve, so
	// no request can race it. The GUI re-pushes the firewall policy.
	firewall.RecoverStaleState()
	if recovered := tunnel.RecoverFromCrash(dataDir); len(recovered) > 0 {
		slog.Warn("recovered from previous crash", "tunnels", recovered)
	}
	network.SetDNSJournalPath(filepath.Join(dataDir, network.DNSJournalFile))
	if restored, err := network.RestoreDNSFromJournal(); err != nil {
		slog.Warn("startup: DNS journal restore failed", "error", err)
	} else if restored {
		slog.Warn("startup: restored original DNS from journal left by previous helper process")
	}

	// OpenVPN manager: the openvpn binary MUST live next to the helper in the
	// root-owned /Library/PrivilegedHelperTools/ (copied and codesign-verified
	// there by the install script). There is deliberately NO fallback to the
	// app bundle: /Applications/LockPlus.app is user-writable, and exec'ing a
	// binary from it as root would let same-user malware escalate. If it's
	// missing, OpenVPN connects fail (ovpn.Manager stats the path) and the
	// user is told to reinstall the helper.
	ovpnBinary := filepath.Join(filepath.Dir(os.Args[0]), "openvpn")
	if _, err := os.Stat(ovpnBinary); err != nil {
		slog.Error("openvpn binary not found next to helper — OpenVPN unavailable; reinstall the helper (relaunch LockPlus and approve the admin prompt)",
			"path", ovpnBinary, "error", err)
	}
	h.ovpnBinary = ovpnBinary
	ovpnRuntimeDir := filepath.Join(dataDir, "ovpn-run")
	h.ovpnManager = ovpn.NewManager(ovpnBinary, ovpnRuntimeDir,
		h.broadcastOvpnStatus,
		h.broadcastAuthPrompt,
		h.onOVPNActiveChange,
	)

	h.monitor = reconnect.NewMonitor(manager, h.reconnectFn, h.onReconnectState, reconnect.DefaultConfig())
	h.monitor.SetFirewallCallbacks(h.holdFirewall, h.releaseFirewall)
	h.monitor.SetShouldReconnect(func(name string) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.autoReconnect[name]
	})
	h.monitor.Start()
	// A tunnel that dies on its own (wireguard-go fatal TUN error, openvpn
	// crash) takes the same reconnect path as a stale handshake.
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

	// SIGTERM (launchctl bootout / kickstart -k on every upgrade) and SIGINT
	// must run the same teardown as a normal Serve return — otherwise pf
	// anchors and networksetup DNS overrides outlive the process. cleanup()
	// is guarded by cleanupOnce, so a concurrent Serve-return cleanup and
	// this path can't double-run it; whichever arrives second just waits.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig.String())
		h.server.Shutdown() // stop serving new RPCs mid-teardown
		h.cleanup()
		os.Exit(0)
	}()

	slog.Info("helper listening", "addr", addr, "pid", os.Getpid(), "daemon", isDaemon())

	// Serve (blocks until shutdown)
	err = h.server.Serve()
	h.cleanup()
	return err
}

// reconnectFn is the reconnect monitor's callback for one tunnel. It takes
// connectMu BEFORE reading the cached config, then re-checks that the tunnel
// is still wanted: a user Disconnect that won the lock has cleared it, and
// reconnecting would resurrect a tunnel the user just turned off.
func (h *Helper) reconnectFn(name string) error {
	h.passResolvedHostnames(name)

	h.connectMu.Lock()
	select {
	case <-h.done:
		h.connectMu.Unlock()
		return fmt.Errorf("helper shutting down: %w", reconnect.ErrGiveUp)
	default:
	}
	h.mu.Lock()
	want := h.autoReconnect[name]
	cfg, isWG := h.activeCfgs[name]
	ovpnContent, isOVPN := h.activeOVPNCfgs[name]
	h.mu.Unlock()
	switch {
	case !want || (!isWG && !isOVPN):
		h.connectMu.Unlock()
		return fmt.Errorf("tunnel %q is no longer wanted: %w", name, reconnect.ErrGiveUp)
	case isWG:
		err := h.manager.Connect(cfg)
		h.connectMu.Unlock()
		if err == nil {
			_ = h.applyFirewall("wg-reconnect")
		}
		return err
	case h.ovpnManager == nil:
		h.connectMu.Unlock()
		return fmt.Errorf("openvpn unavailable: %w", reconnect.ErrGiveUp)
	}
	h.mu.Lock()
	delete(h.ovpnErrors, name)
	h.mu.Unlock()
	err := h.ovpnManager.Connect(name, ovpnContent)
	h.connectMu.Unlock()
	if err != nil {
		return err
	}
	return h.waitOVPNConnected(name)
}

// waitOVPNConnected blocks until an OpenVPN tunnel is CONNECTED with a known
// remote and interface (ovpn.Manager.Connect returns once the process
// starts). Without it the monitor would release the firewall hold before
// the new tunnel could be passed. The deadline (about openvpn's own connect
// timeout) is pushed out while the tunnel waits for the user to type
// credentials, so a 2FA prompt isn't torn down under them.
func (h *Helper) waitOVPNConnected(name string) error {
	const connectTimeout = 90 * time.Second
	deadline := time.Now().Add(connectTimeout)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-h.done:
			return fmt.Errorf("openvpn tunnel %q: helper shutting down", name)
		case <-ticker.C:
		}
		status := h.ovpnManager.GetStatus(name)
		if status == nil {
			return fmt.Errorf("openvpn tunnel %q disappeared while connecting", name)
		}
		switch status.State {
		case domain.StateConnected:
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
	// Kill the stuck attempt so the next retry's Connect starts clean.
	_ = h.ovpnManager.Disconnect(name)
	return fmt.Errorf("openvpn tunnel %q did not connect within %s", name, connectTimeout)
}

// ovpnTunnelHasKnownRemote reports whether name has a known remote address
// and interface (ovpn.Manager.ActiveRemotes), which the firewall needs.
func ovpnTunnelHasKnownRemote(m *ovpn.Manager, name string) bool {
	for _, r := range m.ActiveRemotes() {
		if r.TunnelName == name {
			return true
		}
	}
	return false
}

// onWireGuardEngineDied runs after tunnel.Manager tore down a tunnel whose
// engine died on its own. An auto-reconnect tunnel is held in the firewall
// right away, before the policy is re-applied, so the kill switch never
// opens while the reconnect is pending.
func (h *Helper) onWireGuardEngineDied(name string) {
	h.forgetOrHold(name, func() { delete(h.activeCfgs, name) })
	_ = h.applyFirewall("wg-engine-died")
	h.monitor.NotifyTunnelDied(name)
}

// onOVPNDied runs after an OpenVPN tunnel's process died on its own. The
// firewall was already re-applied by onOVPNActiveChange.
func (h *Helper) onOVPNDied(name string) {
	h.forgetOrHold(name, func() { delete(h.activeOVPNCfgs, name) })
	h.monitor.NotifyTunnelDied(name)
}

// forgetOrHold handles a tunnel that died: held for reconnect if it has
// auto-reconnect on, otherwise its cached state is dropped via forget
// (called with h.mu held).
func (h *Helper) forgetOrHold(name string, forget func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.autoReconnect[name] {
		h.fwHeld[name] = true
		return
	}
	forget()
	delete(h.autoReconnect, name)
}

// broadcastOvpnStatus is the OpenVPN manager's onStatus callback: it pushes
// the merged status immediately instead of waiting for eventLoop's tick.
// An error snapshot is kept (see ovpnErrors) because the manager removes the
// tunnel right after emitting it.
func (h *Helper) broadcastOvpnStatus(status domain.ConnectionStatus) {
	h.recordOVPNStatus(status)
	if h.server == nil {
		return
	}
	h.server.Broadcast(ipc.EventStatus, h.statusDTO())
}

// recordOVPNStatus keeps a tunnel's last error until it next connects.
func (h *Helper) recordOVPNStatus(status domain.ConnectionStatus) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch status.State {
	case domain.StateError:
		if status.ErrorMessage != "" {
			status.Protocol = domain.ProtocolOpenVPN
			h.ovpnErrors[status.TunnelName] = status
		}
	case domain.StateConnected:
		delete(h.ovpnErrors, status.TunnelName)
	}
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

// onOVPNActiveChange is the OpenVPN manager's onActiveChange callback,
// fired when a tunnel reaches CONNECTED or is torn down. A tunnel going down
// while it still has auto-reconnect on was not disconnected by the user
// (handleDisconnect clears the flag first): hold it for the reconnect that
// onOVPNDied is about to start.
func (h *Helper) onOVPNActiveChange(tunnelName string, active bool) {
	reason := "ovpn-connect"
	if !active {
		reason = "ovpn-disconnect"
		h.mu.Lock()
		if h.autoReconnect[tunnelName] {
			h.fwHeld[tunnelName] = true
		}
		h.mu.Unlock()
	}
	_ = h.applyFirewall(reason)
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

// anyTunnelActive reports whether any WireGuard or OpenVPN tunnel is active.
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

// startShutdownTimer (re)starts the grace-window countdown when the GUI's
// control connection drops (non-daemon mode only). Like wg-quick, the helper
// never exits while a tunnel is active.
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
		// Wait out any in-flight connect/reconnect, then tear tunnels down
		// (DisconnectAll includes still-connecting ones). Firewall last, so
		// nothing leaks in between; applyFirewall is a no-op once done is
		// closed, and fwMu waits out an apply already in flight.
		h.connectMu.Lock()
		defer h.connectMu.Unlock()
		h.manager.DisconnectAll()
		if h.ovpnManager != nil {
			h.ovpnManager.Stop()
		}
		h.fwMu.Lock()
		_ = h.firewall.Cleanup()
		h.fwMu.Unlock()
		slog.Info("helper shutdown complete")
	})
}
