package ovpn

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/steiale/wireguide/internal/domain"
)

// authReply carries the credentials FeedCredentials passes back to a connect
// goroutine that is blocked waiting on a >PASSWORD: prompt.
type authReply struct {
	username string
	password string // full password = basePassword + totpCode, already combined
}

// entry is one running OpenVPN tunnel.
type entry struct {
	cmd    *exec.Cmd
	mgmt   *mgmtClient
	status domain.ConnectionStatus
	authCh chan authReply // buffered(1); FeedCredentials sends here
	logPath string
}

// Manager supervises OpenVPN subprocesses, one per active tunnel. It mirrors
// the responsibilities of tunnel.Manager (WireGuard) but for the openvpn
// binary driven over its management interface.
type Manager struct {
	mu         sync.Mutex
	tunnels    map[string]*entry // name → running tunnel
	binaryPath string
	runtimeDir string // e.g. "/var/run/wireguide"

	// onStatus is called whenever a tunnel's status changes (state or bytes).
	onStatus func(domain.ConnectionStatus)
	// onAuthNeeded signals the GUI that a tunnel is waiting for credentials.
	onAuthNeeded func(tunnelName string)
}

// NewManager constructs an OpenVPN Manager. binaryPath is the absolute path to
// the bundled openvpn executable; runtimeDir is a writable directory for
// per-tunnel runtime config, management sockets, and logs.
func NewManager(binaryPath, runtimeDir string, onStatus func(domain.ConnectionStatus), onAuthNeeded func(tunnelName string)) *Manager {
	return &Manager{
		tunnels:      make(map[string]*entry),
		binaryPath:   binaryPath,
		runtimeDir:   runtimeDir,
		onStatus:     onStatus,
		onAuthNeeded: onAuthNeeded,
	}
}

// runtime file paths for a tunnel.
func (m *Manager) configPath(name string) string { return filepath.Join(m.runtimeDir, name+".ovpn") }
func (m *Manager) sockPath(name string) string   { return filepath.Join(m.runtimeDir, name+".mgmt.sock") }
func (m *Manager) logPath(name string) string    { return filepath.Join(m.runtimeDir, name+".log") }

// Connect starts an OpenVPN tunnel from the given raw .ovpn content. It returns
// once the subprocess has been started and supervision goroutines are running —
// the actual CONNECTED transition (and any auth prompt) happens asynchronously
// and is reported via onStatus / onAuthNeeded.
func (m *Manager) Connect(name string, ovpnContent []byte) error {
	m.mu.Lock()
	if _, ok := m.tunnels[name]; ok {
		m.mu.Unlock()
		return fmt.Errorf("openvpn tunnel %q already active", name)
	}
	m.mu.Unlock()

	if m.binaryPath == "" {
		return fmt.Errorf("openvpn binary path not configured")
	}
	if _, err := os.Stat(m.binaryPath); err != nil {
		return fmt.Errorf("openvpn binary not found at %q: %w", m.binaryPath, err)
	}

	// 1. Ensure runtime dir exists (0700 — sockets and logs may be sensitive).
	if err := os.MkdirAll(m.runtimeDir, 0700); err != nil {
		return fmt.Errorf("creating runtime dir: %w", err)
	}

	sockPath := m.sockPath(name)
	cfgPath := m.configPath(name)
	logFile := m.logPath(name)

	// 2. Remove any stale socket left by a previous crashed run.
	_ = os.Remove(sockPath)

	// 3. Write the user's .ovpn verbatim (no appended directives). Management
	// parameters are passed as CLI flags below so they cannot be overridden by
	// a malicious directive in the config file.
	if err := os.WriteFile(cfgPath, ovpnContent, 0600); err != nil {
		return fmt.Errorf("writing runtime config: %w", err)
	}

	// 4. Start the openvpn subprocess. Management flags as CLI args take
	// precedence over any conflicting directives in the config file.
	// --script-security 0 prevents execution of up/down/plugin scripts.
	cmd := exec.Command(m.binaryPath,
		"--config", cfgPath,
		"--management", sockPath, "unix",
		"--management-hold",
		"--management-query-passwords",
		"--script-security", "0",
		"--log", logFile,
	)
	cmd.Dir = m.runtimeDir
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting openvpn: %w", err)
	}

	e := &entry{
		cmd:     cmd,
		authCh:  make(chan authReply, 1),
		logPath: logFile,
		status: domain.ConnectionStatus{
			State:      domain.StateConnecting,
			TunnelName: name,
			Protocol:   domain.ProtocolOpenVPN,
		},
	}
	m.mu.Lock()
	m.tunnels[name] = e
	m.mu.Unlock()

	m.emitStatus(name)

	// 5. Supervise in a goroutine: attach to management, release hold, read loop.
	go m.supervise(name, e)

	return nil
}

// supervise attaches to the management interface and runs the read loop until
// the tunnel exits. It also reaps the subprocess.
func (m *Manager) supervise(name string, e *entry) {
	mgmt, err := dialManagement(m.sockPath(name))
	if err != nil {
		slog.Error("ovpn: failed to attach to management interface", "tunnel", name, "error", err)
		m.setError(name, fmt.Sprintf("management attach failed: %v", err))
		_ = e.cmd.Process.Kill()
		_ = e.cmd.Wait()
		m.cleanup(name)
		return
	}

	m.mu.Lock()
	e.mgmt = mgmt
	m.mu.Unlock()

	if err := mgmt.holdRelease(); err != nil {
		slog.Warn("ovpn: hold release failed", "tunnel", name, "error", err)
	}

	// The read loop blocks until the management connection closes.
	mgmt.readLoop(
		func(state string) { m.onMgmtState(name, state) },
		func(rx, tx int64) { m.onMgmtBytes(name, rx, tx) },
		func() { m.onMgmtAuthPrompt(name, e) },
		func() { /* readLoop done — handled below */ },
	)

	// Management connection ended → openvpn is shutting down or dead. Reap it.
	_ = e.cmd.Wait()
	slog.Info("ovpn: tunnel process exited", "tunnel", name)
	m.cleanup(name)
}

// onMgmtState maps an OpenVPN management state string to a domain state.
func (m *Manager) onMgmtState(name, state string) {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	if !ok {
		m.mu.Unlock()
		return
	}
	switch state {
	case "CONNECTED":
		e.status.State = domain.StateConnected
		if e.status.ConnectedAt.IsZero() {
			e.status.ConnectedAt = time.Now()
		}
		e.status.HasHandshake = true
		e.status.LastHandshakeTime = time.Now()
	case "EXITING":
		e.status.State = domain.StateDisconnected
	case "RECONNECTING":
		e.status.State = domain.StateConnecting
	default:
		// CONNECTING, WAIT, AUTH, GET_CONFIG, ASSIGN_IP, ADD_ROUTES, etc.
		if e.status.State != domain.StateConnected {
			e.status.State = domain.StateConnecting
		}
	}
	m.mu.Unlock()
	slog.Debug("ovpn: state change", "tunnel", name, "state", state)
	m.emitStatus(name)
}

// onMgmtBytes records the latest byte counters and refreshes the duration.
func (m *Manager) onMgmtBytes(name string, rx, tx int64) {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	if !ok {
		m.mu.Unlock()
		return
	}
	e.status.RxBytes = rx
	e.status.TxBytes = tx
	if !e.status.ConnectedAt.IsZero() {
		e.status.Duration = domain.FormatDuration(time.Since(e.status.ConnectedAt))
	}
	if !e.status.LastHandshakeTime.IsZero() {
		e.status.LastHandshake = domain.FormatDuration(time.Since(e.status.LastHandshakeTime))
	}
	m.mu.Unlock()
	m.emitStatus(name)
}

// onMgmtAuthPrompt is invoked when the server requests credentials. It signals
// the GUI and blocks (in this goroutine — the management read loop) until
// FeedCredentials supplies them or a timeout elapses.
func (m *Manager) onMgmtAuthPrompt(name string, e *entry) {
	slog.Info("ovpn: server requesting credentials", "tunnel", name)
	// Drain any stale credential left by a previous timed-out prompt. A
	// TOTP code from an earlier attempt would be expired anyway, and silently
	// reusing it would fail auth without showing the GUI prompt.
	select {
	case <-e.authCh:
		slog.Debug("ovpn: drained stale credential from previous prompt", "tunnel", name)
	default:
	}
	if m.onAuthNeeded != nil {
		m.onAuthNeeded(name)
	}

	select {
	case reply := <-e.authCh:
		m.mu.Lock()
		mgmt := e.mgmt
		m.mu.Unlock()
		if mgmt == nil {
			slog.Warn("ovpn: management gone before credentials arrived", "tunnel", name)
			return
		}
		if err := mgmt.sendCredentials(reply.username, reply.password); err != nil {
			slog.Error("ovpn: sending credentials failed", "tunnel", name, "error", err)
			m.setError(name, fmt.Sprintf("sending credentials failed: %v", err))
		}
	case <-time.After(10 * time.Minute):
		slog.Warn("ovpn: timed out waiting for credentials", "tunnel", name)
		m.setError(name, "timed out waiting for credentials")
		m.Disconnect(name)
	}
}

// FeedCredentials delivers credentials for a tunnel waiting on an auth prompt.
// fullPassword must already be basePassword + totpCode (combined by the caller).
func (m *Manager) FeedCredentials(name, username, fullPassword string) error {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("no active openvpn tunnel %q awaiting credentials", name)
	}
	select {
	case e.authCh <- authReply{username: username, password: fullPassword}:
		return nil
	default:
		return fmt.Errorf("tunnel %q is not waiting for credentials", name)
	}
}

// Disconnect asks an OpenVPN tunnel to shut down cleanly. The actual teardown
// (process reap + cleanup) happens in supervise() once the management
// connection closes.
func (m *Manager) Disconnect(name string) error {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	mgmt := (*mgmtClient)(nil)
	if ok {
		mgmt = e.mgmt
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("openvpn tunnel %q is not active", name)
	}

	if mgmt != nil {
		if err := mgmt.signalTerm(); err != nil {
			slog.Warn("ovpn: SIGTERM via management failed, killing process", "tunnel", name, "error", err)
			_ = e.cmd.Process.Kill()
		}
	} else if e.cmd != nil && e.cmd.Process != nil {
		_ = e.cmd.Process.Kill()
	}
	return nil
}

// GetStatus returns a copy of the status for the named tunnel, or nil.
func (m *Manager) GetStatus(name string) *domain.ConnectionStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.tunnels[name]
	if !ok {
		return nil
	}
	s := e.status
	return &s
}

// ActiveTunnelNames returns the names of all currently active OpenVPN tunnels.
func (m *Manager) ActiveTunnelNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.tunnels))
	for name := range m.tunnels {
		names = append(names, name)
	}
	return names
}

// AllStatuses returns a snapshot copy of every active tunnel's status.
func (m *Manager) AllStatuses() []domain.ConnectionStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]domain.ConnectionStatus, 0, len(m.tunnels))
	for _, e := range m.tunnels {
		out = append(out, e.status)
	}
	return out
}

// Stop disconnects every active OpenVPN tunnel. Used on helper shutdown.
func (m *Manager) Stop() {
	for _, name := range m.ActiveTunnelNames() {
		_ = m.Disconnect(name)
	}
}

// setError marks a tunnel as errored and emits the status.
func (m *Manager) setError(name, msg string) {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	if ok {
		e.status.State = domain.StateError
		e.status.ErrorMessage = msg
	}
	m.mu.Unlock()
	if ok {
		m.emitStatus(name)
	}
}

// emitStatus invokes the onStatus callback with a copy of the tunnel's status.
func (m *Manager) emitStatus(name string) {
	if m.onStatus == nil {
		return
	}
	m.mu.Lock()
	e, ok := m.tunnels[name]
	if !ok {
		m.mu.Unlock()
		return
	}
	s := e.status
	m.mu.Unlock()
	m.onStatus(s)
}

// cleanup removes a tunnel's in-memory entry and its runtime files.
func (m *Manager) cleanup(name string) {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	delete(m.tunnels, name)
	m.mu.Unlock()

	if ok && e.mgmt != nil {
		_ = e.mgmt.close()
	}
	_ = os.Remove(m.sockPath(name))
	_ = os.Remove(m.configPath(name))

	// Emit a final disconnected status so the GUI clears the tunnel.
	if m.onStatus != nil {
		m.onStatus(domain.ConnectionStatus{
			State:      domain.StateDisconnected,
			TunnelName: name,
			Protocol:   domain.ProtocolOpenVPN,
		})
	}
}
