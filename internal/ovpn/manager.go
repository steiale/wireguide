package ovpn

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/network"
	"github.com/steiale/wireguide/internal/storage"
)

// Log lines scraped from openvpn's stdout; the management interface never
// reports the cipher or the utun name, and pushed DNS is applied by us (no
// up-script / dns-updown runs as root).
var (
	cipherLogRe = regexp.MustCompile(`Data Channel: cipher '([^']+)'`)
	ifaceLogRe  = regexp.MustCompile(`(?i)opened \S+ device (\S+)`)
)

// ErrAlreadyActive is returned by Connect when the tunnel already has a
// running openvpn (connected, reconnecting or still tearing down).
var ErrAlreadyActive = errors.New("openvpn tunnel already active")

// stopWait bounds how long Stop waits for every tunnel's teardown (DNS
// restore, runtime files) before killing what is left.
const stopWait = 5 * time.Second

// authReply carries what FeedCredentials passes to a blocked auth prompt.
type authReply struct {
	username string
	password string // basePassword + totpCode, already combined
	response string // challenge answer (CRV1: the whole reply; SCRV1: paired with password)
}

// entry is one running OpenVPN tunnel. Fields are guarded by Manager.mu.
type entry struct {
	cmd      *exec.Cmd
	mgmt     *mgmtClient
	status   domain.ConnectionStatus
	prof     *profile
	authCh   chan authReply // buffered(1)
	scanDone chan struct{}  // closed when scanOutput has drained stdout
	done     chan struct{}  // closed when cleanup has finished

	// active is set once onActiveChange(true) fired and stays set through
	// RECONNECTING, so teardown always revokes the kill-switch pass and a
	// crash mid-reconnect still counts as an unexpected death.
	active bool

	// errMsg is sticky until CONNECTED or new credentials, so later state
	// lines and the final cleanup snapshot don't hide it.
	errMsg string

	dnsApplied bool
	pushDNS    *dnsConfig // pushed DNS accumulated across push-continuation
	pushMore   bool

	awaitingCredentials bool           // lets reconnect polling tell "waiting on a human" from "stuck"
	lastUsername        string         // fallback for CRV1 when the challenge carries none
	pendingChallenge    *AuthChallenge // CRV1 answered on the auth-retry's next Need 'Auth'

	// closeCh unblocks a pending auth prompt on Disconnect.
	closeCh   chan struct{}
	closeOnce sync.Once

	// remoteAddr ("ip:port") seeds the kill-switch pass before CONNECTED;
	// CONNECTED overwrites it with the remote openvpn actually uses.
	remoteAddr  string
	remoteProto string // "udp" | "tcp"

	userInitiated bool // set by Disconnect: not a death worth reconnecting
}

func newEntry(name string, prof *profile) *entry {
	return &entry{
		prof:     prof,
		authCh:   make(chan authReply, 1),
		closeCh:  make(chan struct{}),
		scanDone: make(chan struct{}),
		done:     make(chan struct{}),
		status: domain.ConnectionStatus{
			State:      domain.StateConnecting,
			TunnelName: name,
			Protocol:   domain.ProtocolOpenVPN,
		},
	}
}

// RemoteEndpoint is one connected tunnel's remote, for the kill switch.
type RemoteEndpoint struct {
	TunnelName    string
	InterfaceName string
	Proto         string // "udp" or "tcp"
	Addr          string // "ip:port"
}

// resolveRemoteForKillSwitch resolves the first remote before openvpn
// starts; resolving later could loop the query through the tunnel.
// Best-effort: empty on failure.
func resolveRemoteForKillSwitch(cfg *OVPNConfig) (addr, proto string) {
	if cfg.Remote == "" {
		return "", ""
	}
	host, port, err := net.SplitHostPort(cfg.Remote)
	if err != nil {
		// No port. An unbracketed "v6:port" would parse as a wrong IPv6
		// literal, so only a real bare IP or hostname is accepted.
		if strings.Count(cfg.Remote, ":") >= 2 && !strings.HasPrefix(cfg.Remote, "[") && net.ParseIP(cfg.Remote) == nil {
			slog.Warn("resolveRemoteForKillSwitch: ambiguous unbracketed IPv6 remote", "remote", cfg.Remote)
			return "", ""
		}
		host, port = cfg.Remote, "1194"
	}
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		slog.Warn("resolveRemoteForKillSwitch: DNS resolution failed", "host", host, "error", err)
		return "", ""
	}
	proto = "udp"
	if strings.HasPrefix(cfg.Proto, "tcp") {
		proto = "tcp"
	}
	return net.JoinHostPort(ips[0], port), proto
}

// Manager supervises one openvpn process per tunnel.
type Manager struct {
	mu         sync.Mutex
	tunnels    map[string]*entry
	binaryPath string
	runtimeDir string

	// netMgr applies DNS. Separate from WireGuard's instance; fine while
	// both protocols never push DNS at the same time.
	netMgr network.NetworkManager

	onStatus     func(domain.ConnectionStatus)
	onAuthNeeded func(tunnelName string, challenge *AuthChallenge)
	// onActiveChange fires on each transition into CONNECTED and once on
	// teardown of a tunnel that was active; not on bytecount updates.
	onActiveChange func(tunnelName string, active bool)
	// onDied fires after cleanup of an active tunnel that died without
	// Disconnect (crash or wedged management socket).
	onDied func(name string)
}

// SetOnDied registers the unexpected-death callback. Call before Connect.
func (m *Manager) SetOnDied(fn func(name string)) {
	m.onDied = fn
}

// NewManager constructs a Manager. runtimeDir holds per-tunnel config and
// management sockets.
func NewManager(binaryPath, runtimeDir string, onStatus func(domain.ConnectionStatus), onAuthNeeded func(tunnelName string, challenge *AuthChallenge), onActiveChange func(tunnelName string, active bool)) *Manager {
	return &Manager{
		tunnels:        make(map[string]*entry),
		binaryPath:     binaryPath,
		runtimeDir:     runtimeDir,
		netMgr:         network.NewPlatformManager(),
		onStatus:       onStatus,
		onAuthNeeded:   onAuthNeeded,
		onActiveChange: onActiveChange,
	}
}

func (m *Manager) configPath(name string) string { return filepath.Join(m.runtimeDir, name+".ovpn") }
func (m *Manager) sockPath(name string) string   { return filepath.Join(m.runtimeDir, name+".mgmt.sock") }
func (m *Manager) pidPath(name string) string    { return filepath.Join(m.runtimeDir, name+pidSuffix) }

// Connect starts a tunnel from raw .ovpn content and returns once openvpn is
// running; CONNECTED and auth prompts arrive via the callbacks.
func (m *Manager) Connect(name string, ovpnContent []byte) error {
	// Validated here (not only at IPC) because name becomes a path and the
	// profile runs as root, whoever the caller is.
	if err := storage.ValidateTunnelName(name); err != nil {
		return fmt.Errorf("invalid tunnel name: %w", err)
	}
	prof, err := inspectProfile(ovpnContent)
	if err != nil {
		return err
	}
	if m.binaryPath == "" {
		return fmt.Errorf("openvpn binary path not configured")
	}
	if _, err := os.Stat(m.binaryPath); err != nil {
		return fmt.Errorf("openvpn binary not found at %q: %w", m.binaryPath, err)
	}

	e := newEntry(name, prof)
	// Reserve the name before any slow work so two Connects can't both start.
	m.mu.Lock()
	if _, ok := m.tunnels[name]; ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %q", ErrAlreadyActive, name)
	}
	m.tunnels[name] = e
	m.mu.Unlock()

	cmd, err := m.start(name, e, ovpnContent)
	if err != nil {
		m.mu.Lock()
		delete(m.tunnels, name)
		m.mu.Unlock()
		close(e.done)
		return err
	}
	m.mu.Lock()
	e.cmd = cmd
	cancelled := e.userInitiated
	m.mu.Unlock()
	if cancelled {
		_ = cmd.Process.Kill()
	}
	m.emitStatus(name)
	go m.supervise(name, e)
	return nil
}

// start writes the runtime config and launches openvpn.
func (m *Manager) start(name string, e *entry, ovpnContent []byte) (*exec.Cmd, error) {
	if err := os.MkdirAll(m.runtimeDir, 0700); err != nil {
		return nil, fmt.Errorf("creating runtime dir: %w", err)
	}
	sockPath, cfgPath := m.sockPath(name), m.configPath(name)
	_ = os.Remove(sockPath)
	if err := os.WriteFile(cfgPath, e.prof.runtimeConfig(ovpnContent), 0600); err != nil {
		return nil, fmt.Errorf("writing runtime config: %w", err)
	}
	addr, proto := resolveRemoteForKillSwitch(&e.prof.cfg)
	m.mu.Lock()
	e.remoteAddr, e.remoteProto = addr, proto
	m.mu.Unlock()

	cmd := exec.Command(m.binaryPath, m.args(cfgPath, sockPath, e.prof)...)
	cmd.Dir = m.runtimeDir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("attaching openvpn stdout: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting openvpn: %w", err)
	}
	// Lets the next helper kill this openvpn if we die without cleanup.
	if err := writePIDFile(m.pidPath(name), cmd.Process.Pid); err != nil {
		slog.Warn("ovpn: writing pid file failed", "tunnel", name, "error", err)
	}
	go m.scanOutput(name, e, stdout)
	return cmd, nil
}

// args builds the openvpn command line. Everything after --config overrides
// the profile:
//   - --script-security 1 allows openvpn's own ifconfig/route calls but no
//     user scripts, a second line behind the allowlist.
//   - --dns-updown disable: 2.7 would otherwise run its built-in DNS script
//     as root; we apply DNS ourselves.
//   - --auth-retry interact: re-prompt on auth failure instead of exiting;
//     required for CRV1 (the challenge arrives as a failure).
//   - --persist-tun keeps the same utun across restarts so the kill-switch
//     rule stays valid.
//   - --persist-remote-ip, for a profile with exactly one remote only (after
//     <connection> expansion): keeps the last authenticated remote ip:port
//     (and skips re-resolving) across SIGUSR1/ping-restart restarts, so the
//     CONNECTED-time remote the kill switch passes is the one reused. A
//     multi-remote profile goes without it (it would pin a dead remote); the
//     helper then passes all of its remotes and recycles a process stuck in
//     its own reconnect (see the helper's OpenVPN watchdog).
//   - keepalive/mssfix floors only when the profile sets none, so a
//     provider's tuned values win.
func (m *Manager) args(cfgPath, sockPath string, p *profile) []string {
	args := []string{
		"--config", cfgPath,
		"--management", sockPath, "unix",
		"--management-hold",
		"--management-query-passwords",
		"--script-security", "1",
		"--dns-updown", "disable",
		"--auth-retry", "interact",
		"--persist-tun",
		"--verb", p.runtimeVerb(),
	}
	if p.persistRemoteIP() {
		args = append(args, "--persist-remote-ip")
	}
	if !p.hasKeepalive {
		args = append(args, "--ping", "10", "--ping-restart", "60")
	}
	if !p.hasMTU {
		args = append(args, "--mssfix", "1300")
	}
	if p.legacyCiphers != "" {
		args = append(args, "--data-ciphers", p.legacyCiphers)
	}
	return args
}

// supervise attaches to management, runs the read loop, then reaps.
func (m *Manager) supervise(name string, e *entry) {
	mgmt, err := dialManagement(m.sockPath(name))
	if err != nil {
		m.mu.Lock()
		cancelled := e.userInitiated
		m.mu.Unlock()
		if !cancelled {
			slog.Error("ovpn: failed to attach to management interface", "tunnel", name, "error", err)
			m.fail(name, fmt.Sprintf("management attach failed: %v", err), false)
		}
	} else {
		m.mu.Lock()
		e.mgmt = mgmt
		m.mu.Unlock()
		mgmt.readLoop(&tunnelEvents{m: m, name: name, e: e})
	}
	// The loop ends on close or on a read deadline (wedged process): Kill so
	// Wait can't hang, and drain stdout before Wait closes the pipe.
	_ = e.cmd.Process.Kill()
	<-e.scanDone
	_ = e.cmd.Wait()
	slog.Info("ovpn: tunnel process exited", "tunnel", name)
	m.cleanup(name)
}

// tunnelEvents adapts management notifications to one tunnel.
type tunnelEvents struct {
	m    *Manager
	name string
	e    *entry
}

func (t *tunnelEvents) state(s, localIP, remote string) { t.m.onMgmtState(t.name, s, localIP, remote) }
func (t *tunnelEvents) bytes(rx, tx int64)              { t.m.onMgmtBytes(t.name, rx, tx) }
func (t *tunnelEvents) authPrompt(sc *AuthChallenge)    { t.m.onMgmtAuthPrompt(t.name, t.e, sc) }
func (t *tunnelEvents) dynamicChallenge(ch *AuthChallenge) {
	t.m.onMgmtDynamicChallenge(t.name, t.e, ch)
}
func (t *tunnelEvents) authFailed(msg string) {
	slog.Warn("ovpn: credentials rejected, waiting for re-prompt", "tunnel", t.name, "error", msg)
	t.m.onMgmtAuthFailed(t.name, msg)
}
func (t *tunnelEvents) failure(msg string, terminate bool) {
	slog.Warn("ovpn: tunnel error", "tunnel", t.name, "error", msg)
	t.m.fail(t.name, msg, terminate)
}

// scanOutput forwards openvpn's stdout to slog (Debug) and scrapes the
// cipher, utun name and pushed DNS.
func (m *Manager) scanOutput(name string, e *entry, r io.Reader) {
	defer close(e.scanDone)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		slog.Debug("ovpn: "+line, "tunnel", name)
		switch {
		case strings.Contains(line, "Data Channel: cipher"):
			if mm := cipherLogRe.FindStringSubmatch(line); mm != nil {
				m.update(name, func(e *entry) { e.status.Cipher = mm[1] })
			}
		case strings.Contains(line, "Received control message: 'PUSH_"):
			if msg, ok := parsePushLine(line, e.prof.pullFilters); ok {
				m.onPush(name, e, msg)
			}
		case strings.Contains(line, "Initialization Sequence Completed"):
			// Profile-defined DNS with nothing pushed (or no pull at all).
			m.mu.Lock()
			need := !e.dnsApplied
			m.mu.Unlock()
			if need {
				m.applyDNS(name, e.prof.dns.entries())
			}
		default:
			if mm := ifaceLogRe.FindStringSubmatch(line); mm != nil {
				m.setInterface(name, mm[1])
			}
		}
	}
}

// setInterface records the utun name scraped from stdout. It can arrive
// after CONNECTED (another goroutine reads the management socket); an
// active tunnel then gets its firewall pass re-applied, since the apply at
// CONNECTED had to skip it.
func (m *Manager) setInterface(name, iface string) {
	var reapply bool
	m.update(name, func(e *entry) {
		reapply = e.active && e.status.InterfaceName == ""
		e.status.InterfaceName = iface
	})
	if reapply && m.onActiveChange != nil {
		m.onActiveChange(name, true)
	}
}

// onPush merges pushed DNS with the profile's and applies it.
func (m *Manager) onPush(name string, e *entry, msg pushMessage) {
	if msg.rejected {
		return // openvpn discards the push and restarts
	}
	m.mu.Lock()
	switch {
	case msg.update:
		// PUSH_UPDATE replaces DNS only if it carries DNS options.
		if !msg.dns.touched {
			m.mu.Unlock()
			return
		}
		d := msg.dns
		e.pushDNS = &d
	case e.pushDNS == nil || !e.pushMore:
		d := msg.dns
		e.pushDNS = &d
	default:
		e.pushDNS = mergePtr(e.pushDNS, msg.dns)
	}
	e.pushMore = msg.more
	merged := e.prof.dns.merge(*e.pushDNS)
	m.mu.Unlock()
	m.applyDNS(name, merged.entries())
}

func mergePtr(a *dnsConfig, b dnsConfig) *dnsConfig {
	d := a.merge(b)
	d.touched = a.touched || b.touched
	return &d
}

// applyDNS sets the tunnel's resolvers via netMgr (like WireGuard's DNS =).
func (m *Manager) applyDNS(name string, entries []string) {
	if len(entries) == 0 || m.netMgr == nil {
		return
	}
	if err := m.netMgr.SetDNS(name, entries); err != nil {
		slog.Warn("ovpn: failed to apply DNS", "tunnel", name, "entries", entries, "error", err)
		return
	}
	// Status reports only server IPs, not search domains.
	var ips []string
	for _, v := range entries {
		if net.ParseIP(v) != nil {
			ips = append(ips, v)
		}
	}
	if !m.update(name, func(e *entry) { e.dnsApplied = true; e.status.DNSServers = ips }) {
		// Tunnel cleaned up while SetDNS ran; nobody else will restore.
		_ = m.netMgr.RestoreDNS(name)
		return
	}
	slog.Info("ovpn: applied DNS", "tunnel", name, "entries", entries)
}

// update applies fn to the tunnel's entry under the lock and emits the
// status. Returns false if the tunnel is gone.
func (m *Manager) update(name string, fn func(e *entry)) bool {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	if ok {
		fn(e)
	}
	m.mu.Unlock()
	if ok {
		m.emitStatus(name)
	}
	return ok
}

// onMgmtState maps a management state to a domain state. The CONNECTED
// remote replaces the Connect-time guess so the kill switch follows
// openvpn's own failover.
func (m *Manager) onMgmtState(name, state, localIP, remoteAddr string) {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	if !ok {
		m.mu.Unlock()
		return
	}
	wasConnected := e.status.State == domain.StateConnected
	switch state {
	case "CONNECTED":
		e.status.State = domain.StateConnected
		e.errMsg, e.status.ErrorMessage = "", ""
		if e.status.ConnectedAt.IsZero() {
			e.status.ConnectedAt = time.Now()
		}
		e.status.HasHandshake = true
		e.status.LastHandshakeTime = time.Now()
		if localIP != "" {
			e.status.Address = localIP
		}
		if remoteAddr != "" {
			e.remoteAddr = remoteAddr
		}
	case "EXITING":
		e.status.State = domain.StateDisconnected
	default:
		// RECONNECTING, WAIT, AUTH, GET_CONFIG, ... (CONNECTED is only left
		// via RECONNECTING/EXITING).
		if state == "RECONNECTING" || e.status.State != domain.StateConnected {
			e.status.State = domain.StateConnecting
		}
	}
	if e.errMsg != "" && e.status.State != domain.StateConnected {
		e.status.State = domain.StateError
	}
	nowConnected := e.status.State == domain.StateConnected
	becameActive := nowConnected && !wasConnected
	if becameActive {
		e.active = true
	}
	m.mu.Unlock()
	slog.Debug("ovpn: state change", "tunnel", name, "state", state)
	m.emitStatus(name)
	if becameActive && m.onActiveChange != nil {
		m.onActiveChange(name, true)
	}
}

func (m *Manager) onMgmtBytes(name string, rx, tx int64) {
	m.update(name, func(e *entry) {
		e.status.RxBytes, e.status.TxBytes = rx, tx
		if !e.status.ConnectedAt.IsZero() {
			e.status.Duration = domain.FormatDuration(time.Since(e.status.ConnectedAt))
		}
		if !e.status.LastHandshakeTime.IsZero() {
			e.status.LastHandshake = domain.FormatDuration(time.Since(e.status.LastHandshakeTime))
		}
	})
}

// onMgmtAuthFailed handles "Verification Failed: 'Auth'". With
// --auth-retry interact openvpn restarts and asks again, so this is not
// terminal: the state stays Connecting and the text is only carried as the
// error message, for the re-prompt to show.
func (m *Manager) onMgmtAuthFailed(name, msg string) {
	m.update(name, func(e *entry) {
		e.status.ErrorMessage = msg
		if e.errMsg == "" && e.status.State == domain.StateError {
			e.status.State = domain.StateConnecting
		}
	})
}

// onMgmtAuthPrompt handles Need 'Auth': notify the GUI and block the read
// loop until FeedCredentials, Disconnect or a timeout. A pending CRV1
// challenge means this is the auth-retry it triggered; the GUI already has
// that prompt open, so it isn't re-notified. A prompt means openvpn is alive
// and retrying, so any earlier error stops being the tunnel's state (its
// text stays as the error message).
func (m *Manager) onMgmtAuthPrompt(name string, e *entry, sc *AuthChallenge) {
	slog.Info("ovpn: server requesting credentials", "tunnel", name)

	m.mu.Lock()
	challenge, notifyGUI := sc, true
	if challenge == nil && e.pendingChallenge != nil {
		challenge, notifyGUI = e.pendingChallenge, false
	}
	e.awaitingCredentials = true
	e.errMsg = ""
	if e.status.State == domain.StateError {
		e.status.State = domain.StateConnecting
	}
	m.mu.Unlock()
	m.emitStatus(name)

	if notifyGUI {
		// A stale reply (e.g. an expired TOTP from a timed-out prompt) would
		// silently fail auth. Not drained for a CRV1 retry: the user may
		// have answered already.
		select {
		case <-e.authCh:
		default:
		}
		if m.onAuthNeeded != nil {
			m.onAuthNeeded(name, challenge)
		}
	}

	defer func() {
		m.mu.Lock()
		e.awaitingCredentials = false
		m.mu.Unlock()
	}()
	select {
	case reply := <-e.authCh:
		m.mu.Lock()
		mgmt := e.mgmt
		e.pendingChallenge = nil
		username, password := reply.username, reply.password
		switch {
		case challenge != nil && challenge.Kind == ChallengeDynamic:
			username = challenge.username
			if username == "" {
				username = e.lastUsername
			}
			password = fmt.Sprintf("CRV1::%s::%s", challenge.StateID, reply.response)
		case challenge != nil && challenge.Kind == ChallengeStatic:
			password = combineStaticChallenge(challenge, reply.password, reply.response)
		}
		if username != "" {
			e.lastUsername = username
		}
		// New credentials clear a previous auth failure.
		e.errMsg, e.status.ErrorMessage = "", ""
		if e.status.State == domain.StateError {
			e.status.State = domain.StateConnecting
		}
		m.mu.Unlock()
		m.emitStatus(name)
		if mgmt == nil {
			return
		}
		slog.Debug("ovpn: sending credentials", "tunnel", name, "username", username, "challenge_kind", challengeKindOf(challenge))
		if err := mgmt.sendCredentials(username, password); err != nil {
			m.fail(name, fmt.Sprintf("sending credentials failed: %v", err), false)
		}
	case <-e.closeCh:
		slog.Info("ovpn: tunnel disconnected while awaiting credentials", "tunnel", name)
	case <-time.After(10 * time.Minute):
		m.fail(name, "timed out waiting for credentials", true)
	}
}

// IsAwaitingCredentials reports whether the tunnel is blocked on an auth
// prompt.
func (m *Manager) IsAwaitingCredentials(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.tunnels[name]
	return ok && e.awaitingCredentials
}

// onMgmtDynamicChallenge stores a CRV1 challenge for the next Need 'Auth'
// and notifies the GUI without blocking the read loop.
func (m *Manager) onMgmtDynamicChallenge(name string, e *entry, ch *AuthChallenge) {
	slog.Info("ovpn: server issued a dynamic challenge", "tunnel", name)
	m.mu.Lock()
	e.pendingChallenge = ch
	m.mu.Unlock()
	select {
	case <-e.authCh:
	default:
	}
	if m.onAuthNeeded != nil {
		m.onAuthNeeded(name, ch)
	}
}

// combineStaticChallenge formats password+response per SCRV1's Concat flag.
func combineStaticChallenge(ch *AuthChallenge, password, response string) string {
	if ch.Concat {
		return password + response
	}
	return fmt.Sprintf("SCRV1:%s:%s",
		base64.StdEncoding.EncodeToString([]byte(password)),
		base64.StdEncoding.EncodeToString([]byte(response)))
}

func challengeKindOf(ch *AuthChallenge) ChallengeKind {
	if ch == nil {
		return ChallengeNone
	}
	return ch.Kind
}

// FeedCredentials delivers a reply to a tunnel waiting on an auth prompt.
// fullPassword is basePassword+TOTP; response answers a challenge (CRV1: the
// whole reply, SCRV1: paired with fullPassword).
func (m *Manager) FeedCredentials(name, username, fullPassword, response string) error {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("no active openvpn tunnel %q awaiting credentials", name)
	}
	select {
	case e.authCh <- authReply{username: username, password: fullPassword, response: response}:
		return nil
	default:
		return fmt.Errorf("tunnel %q is not waiting for credentials", name)
	}
}

// persistRemoteIP reports whether --persist-remote-ip is safe: only with a
// single remote. Upstream FIXME (openvpn init.c ~544-568, next_connection_entry):
// persist-remote-ip is broken with connection lists/multiple remotes.
func (p *profile) persistRemoteIP() bool { return len(p.cfg.Remotes) == 1 }

// Recycle stops a running tunnel's openvpn as an unexpected death (not a
// user disconnect): an active tunnel is then reported through onDied, so
// the helper holds it and the reconnect monitor starts a fresh process, or,
// without auto-reconnect, the kill switch keeps it blocked.
func (m *Manager) Recycle(name string) error {
	return m.stop(name, false)
}

// Disconnect asks openvpn to exit; supervise reaps and cleans up.
func (m *Manager) Disconnect(name string) error {
	return m.stop(name, true)
}

// stop asks openvpn to exit. user marks the teardown as the user's own, so
// it is not reported as an unexpected death; a terminal failure (fail) stops
// with user=false, so an active tunnel that fails is still a death that the
// kill switch and reconnect logic react to.
func (m *Manager) stop(name string, user bool) error {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	var mgmt *mgmtClient
	var cmd *exec.Cmd
	if ok {
		if user {
			e.userInitiated = true
		}
		mgmt, cmd = e.mgmt, e.cmd
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("openvpn tunnel %q is not active", name)
	}
	e.closeOnce.Do(func() { close(e.closeCh) })

	switch {
	case mgmt != nil:
		if err := mgmt.signalTerm(); err != nil {
			slog.Warn("ovpn: SIGTERM via management failed, killing process", "tunnel", name, "error", err)
			_ = cmd.Process.Kill()
		}
	case cmd != nil && cmd.Process != nil:
		_ = cmd.Process.Kill()
	}
	return nil
}

// GetStatus returns a copy of the tunnel's status, or nil.
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

// ActiveTunnelNames returns the names of all running tunnels.
func (m *Manager) ActiveTunnelNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.tunnels))
	for name := range m.tunnels {
		names = append(names, name)
	}
	return names
}

// AllStatuses returns a copy of every running tunnel's status.
func (m *Manager) AllStatuses() []domain.ConnectionStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]domain.ConnectionStatus, 0, len(m.tunnels))
	for _, e := range m.tunnels {
		out = append(out, e.status)
	}
	return out
}

// ActiveRemotes returns the remote of every active tunnel (including one
// reconnecting after a ping-restart) whose remote and utun are known.
func (m *Manager) ActiveRemotes() []RemoteEndpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []RemoteEndpoint
	for name, e := range m.tunnels {
		if !e.active || e.remoteAddr == "" || e.status.InterfaceName == "" {
			continue
		}
		out = append(out, RemoteEndpoint{
			TunnelName:    name,
			InterfaceName: e.status.InterfaceName,
			Proto:         e.remoteProto,
			Addr:          e.remoteAddr,
		})
	}
	return out
}

// Stop disconnects every tunnel (helper shutdown) and waits, up to
// stopWait, for each teardown (DNS restore, runtime files) to finish, so
// the caller's own cleanup and exit run after it. Stragglers are killed.
// Finally the DNS route monitor is stopped.
func (m *Manager) Stop() {
	m.mu.Lock()
	entries := make(map[string]*entry, len(m.tunnels))
	for name, e := range m.tunnels {
		entries[name] = e
	}
	m.mu.Unlock()
	for name := range entries {
		_ = m.Disconnect(name)
	}
	deadline := time.Now().Add(stopWait)
	for name, e := range entries {
		select {
		case <-e.done:
			continue
		case <-time.After(time.Until(deadline)):
		}
		slog.Warn("ovpn: teardown did not finish in time, killing openvpn", "tunnel", name)
		m.mu.Lock()
		cmd := e.cmd
		m.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-e.done:
		case <-time.After(time.Second):
		}
	}
	m.stopDNSMonitor()
}

// stopDNSMonitor stops the route monitor SetDNS started on the shared
// netMgr (it re-applies DNS on network changes); a later SetDNS starts a
// fresh one.
func (m *Manager) stopDNSMonitor() {
	if s, ok := m.netMgr.(interface{ StopMonitor() }); ok {
		s.StopMonitor()
	}
}

// fail records a user-visible error; terminate also stops openvpn, which
// would otherwise wait for input we can't provide.
func (m *Manager) fail(name, msg string, terminate bool) {
	m.update(name, func(e *entry) {
		e.errMsg = msg
		e.status.State = domain.StateError
		e.status.ErrorMessage = msg
	})
	if terminate {
		_ = m.stop(name, false)
	}
}

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

// cleanup removes the tunnel's entry and runtime files. An active tunnel
// that died on its own is reported through onDied only (not
// onActiveChange(false)): the helper then holds or blocks it in the same
// firewall apply, instead of first dropping its pass.
func (m *Manager) cleanup(name string) {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	delete(m.tunnels, name)
	otherDNS := false
	for _, o := range m.tunnels {
		otherDNS = otherDNS || o.dnsApplied
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	defer close(e.done)
	died := e.active && !e.userInitiated && m.onDied != nil
	if e.active && !died && m.onActiveChange != nil {
		m.onActiveChange(name, false)
	}
	if e.mgmt != nil {
		_ = e.mgmt.close()
	}
	if e.dnsApplied && m.netMgr != nil {
		if err := m.netMgr.RestoreDNS(name); err != nil {
			slog.Warn("ovpn: failed to restore DNS", "tunnel", name, "error", err)
		}
		if !otherDNS {
			m.stopDNSMonitor()
		}
	}
	_ = os.Remove(m.sockPath(name))
	_ = os.Remove(m.configPath(name))
	_ = os.Remove(m.pidPath(name))

	final := domain.ConnectionStatus{State: domain.StateDisconnected, TunnelName: name, Protocol: domain.ProtocolOpenVPN}
	if e.errMsg != "" {
		final.State, final.ErrorMessage = domain.StateError, e.errMsg
	}
	if m.onStatus != nil {
		m.onStatus(final)
	}
	// Last: onDied may synchronously reconnect under the same name, so files
	// and DNS of this instance must already be gone.
	if died {
		slog.Warn("ovpn: tunnel died unexpectedly", "tunnel", name)
		m.onDied(name)
	}
}
