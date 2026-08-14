package ovpn

import (
	"bufio"
	"encoding/base64"
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

// cipherLogRe matches OpenVPN's own startup log line announcing the
// negotiated data-channel cipher, e.g.:
//
//	Data Channel: cipher 'AES-256-GCM'
//	Data Channel: cipher 'AES-256-GCM', auth 'SHA256'
//
// See src/openvpn/init.c in the OpenVPN 2.6 source.
var cipherLogRe = regexp.MustCompile(`Data Channel: cipher '([^']+)'`)

// dhcpOptionRe matches server-pushed DNS server / search domain options out
// of OpenVPN's own log line announcing the PUSH_REPLY, e.g.:
//
//	PUSH: Received control message: 'PUSH_REPLY,...,dhcp-option DNS 192.168.1.11,dhcp-option DNS 192.168.1.14,dhcp-option DOMAIN all-service.local,ifconfig ...'
//
// OpenVPN's core applies routes/ifconfig from PUSH_REPLY itself but never
// touches the OS resolver — that's normally the job of an --up/--route-up
// script reading the foreign_option_N env vars OpenVPN sets, which we don't
// have (and OpenVPN's own built-in dns-updown helper isn't present in our
// static build either). So we parse the pushed options directly from this
// log line instead and apply them the same way WireGuard's `DNS = ...`
// directive does, via network.NetworkManager/networksetup.
//
// Values are terminated by a comma, not whitespace — the whole PUSH_REPLY
// options list is comma-separated with no spaces around the commas. Also
// exclude the closing quote: OpenVPN logs the whole PUSH_REPLY wrapped in
// single quotes, and when a dhcp-option is the LAST option in the (possibly
// fragmented, if the option list is long) logged line, [^,]+ alone would
// swallow that trailing quote into the captured value.
var dhcpOptionRe = regexp.MustCompile(`dhcp-option (DNS|DOMAIN) ([^,']+)`)

// ifaceLogRe matches OpenVPN's own log line announcing the tun/utun device
// it just opened, e.g. "Opened utun device utun5" on macOS. Unlike
// WireGuard, OpenVPN's management interface never reports the OS interface
// name via >STATE: or any other structured notification — this stdout line
// is the only place it appears — so DNS protection (and any other feature
// needing to reference the OVPN tunnel's interface, e.g. a future kill
// switch pass-rule) has to scrape it the same way cipherLogRe/dhcpOptionRe
// already do for other openvpn-log-only information.
var ifaceLogRe = regexp.MustCompile(`(?i)opened \S+ device (\S+)`)

// authReply carries the credentials FeedCredentials passes back to a connect
// goroutine that is blocked waiting on a >PASSWORD: prompt.
type authReply struct {
	username string
	password string // full password = basePassword + totpCode, already combined

	// response is the user's answer to a challenge/response prompt (dynamic
	// CRV1: the ENTIRE reply, password is unused; static SCRV1: paired with
	// password, combined per the challenge's Concat flag). Empty/unused for
	// a plain prompt.
	response string
}

// entry is one running OpenVPN tunnel.
type entry struct {
	cmd        *exec.Cmd
	mgmt       *mgmtClient
	status     domain.ConnectionStatus
	authCh     chan authReply // buffered(1); FeedCredentials sends here
	dnsApplied bool           // true once applyPushedDNS has set DNS for this tunnel

	// lastUsername is the username most recently sent to the management
	// socket. Reused when responding to a CRV1 dynamic challenge, whose
	// prompt carries no username field of its own (the frontend shows a
	// response-only form at that point — see onMgmtAuthPrompt).
	lastUsername string

	// pendingChallenge is set when a dynamic (CRV1) challenge has been
	// issued (a "Verification Failed" line with a CRV1 payload) but not yet
	// answered — the response is collected now, then actually sent once
	// OpenVPN's auth-retry brings a fresh "Need 'Auth'" prompt. nil
	// otherwise. See onMgmtDynamicChallenge/onMgmtAuthPrompt.
	pendingChallenge *AuthChallenge

	// closeCh is closed by Disconnect to unblock onMgmtAuthPrompt if it's
	// currently blocked waiting for the user to answer a prompt. Without
	// this, disconnecting a tunnel mid-prompt (e.g. the user cancels the
	// auth modal) has no way to reach the read-loop goroutine — it's
	// blocked on a channel receive, not on the management socket, so the
	// process dying doesn't wake it — leaving the tunnel showing
	// "connecting" for up to the full 10-minute credential timeout even
	// though the user already asked to disconnect.
	closeCh   chan struct{}
	closeOnce sync.Once

	// remoteAddr/remoteProto are the tunnel's resolved remote server ("ip:port")
	// and normalized protocol ("udp" or "tcp"), resolved once at Connect time —
	// see resolveRemoteForKillSwitch. Used by the kill switch to build a
	// pass-rule for this tunnel's traffic. Empty if the config had no usable
	// remote directive or DNS resolution failed.
	remoteAddr  string
	remoteProto string
}

// RemoteEndpoint describes one connected OpenVPN tunnel's resolved remote
// server, for the kill switch to whitelist alongside WireGuard's endpoints.
type RemoteEndpoint struct {
	TunnelName    string
	InterfaceName string
	Proto         string // "udp" or "tcp"
	Addr          string // "ip:port"
}

// resolveRemoteForKillSwitch resolves an .ovpn config's "remote" directive to
// a literal IP:port and normalizes its protocol, for building a kill-switch
// pass-rule. Resolution happens once, here, before the openvpn subprocess
// starts — resolving later (e.g. on-demand when the user toggles the kill
// switch after the tunnel is already up and possibly routing all traffic)
// would risk the DNS query looping back through the tunnel itself, exactly
// the reason WireGuard's endpoints are resolved before its routes are
// installed too. Best-effort: returns empty strings (never an error) since a
// failure here should not block the tunnel from connecting — it just means
// the kill switch won't be able to whitelist this tunnel until reconnected.
//
// This resolved address is only a best-effort SEED for entry.remoteAddr,
// used before the tunnel has ever reached CONNECTED (e.g. while the kill
// switch's ActiveRemotes is consulted mid-connect). Once CONNECTED,
// onMgmtState overwrites entry.remoteAddr with the LIVE remote OpenVPN's
// own >STATE: line reports (see readLoop's doc comment) — which correctly
// reflects OpenVPN's own internal reconnects to a different `remote`
// directive or a different round-robin DNS answer, since that's OpenVPN
// itself telling us what it's actually using right now, not a value we
// resolved once ourselves.
func resolveRemoteForKillSwitch(cfg *OVPNConfig) (addr, proto string) {
	if cfg.Remote == "" {
		return "", ""
	}
	host, port, err := net.SplitHostPort(cfg.Remote)
	if err != nil {
		// ParseOVPN brackets IPv6 hosts before appending a port
		// ("[2001:db8::1]:1194"), so SplitHostPort failing here should only
		// mean "no port at all" (a bare hostname or IPv6 literal). If the
		// string still has 2+ colons and isn't bracketed, treat it as
		// unparseable rather than guessing — an unbracketed
		// "ipv6host:port"-shaped string is itself a syntactically valid but
		// WRONG IPv6 literal (the port digits get absorbed as the address's
		// last hextet), which would resolve "successfully" to the wrong
		// address and let the kill switch whitelist it instead of the real
		// remote. But a BARE IPv6 host with no port at all (e.g. plain
		// "remote 2001:db8::1", never bracketed by ParseOVPN since there's
		// no port to append) is itself a valid, unambiguous IP literal —
		// net.ParseIP distinguishes that legitimate case from the
		// ambiguous "host:port glued together" shape, which never parses
		// as a literal IP on its own.
		if strings.Count(cfg.Remote, ":") >= 2 && !strings.HasPrefix(cfg.Remote, "[") && net.ParseIP(cfg.Remote) == nil {
			slog.Warn("resolveRemoteForKillSwitch: ambiguous unbracketed IPv6 remote, refusing to guess — kill switch will not whitelist this tunnel",
				"remote", cfg.Remote)
			return "", ""
		}
		host = cfg.Remote
		port = "1194" // OpenVPN's default port when unspecified
	}
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		slog.Warn("resolveRemoteForKillSwitch: DNS resolution failed, kill switch cannot whitelist this tunnel yet",
			"host", host, "error", err)
		return "", ""
	}
	proto = "udp"
	if strings.HasPrefix(cfg.Proto, "tcp") {
		proto = "tcp"
	}
	return net.JoinHostPort(ips[0], port), proto
}

// Manager supervises OpenVPN subprocesses, one per active tunnel. It mirrors
// the responsibilities of tunnel.Manager (WireGuard) but for the openvpn
// binary driven over its management interface.
type Manager struct {
	mu         sync.Mutex
	tunnels    map[string]*entry // name → running tunnel
	binaryPath string
	runtimeDir string // e.g. "/var/run/wireguide"

	// netMgr applies server-pushed DNS (see dhcpOptionRe/applyPushedDNS). A
	// dedicated instance, separate from WireGuard's tunnel.Manager's own
	// network.NetworkManager — simplest way to avoid the two protocols
	// racing on shared save/restore state. Fine as long as OVPN and a
	// DNS-pushing WireGuard tunnel are never both active at once; revisit if
	// that changes.
	netMgr network.NetworkManager

	// onStatus is called whenever a tunnel's status changes (state or bytes).
	onStatus func(domain.ConnectionStatus)
	// onAuthNeeded signals the GUI that a tunnel is waiting for credentials.
	// challenge is non-nil if this prompt carries a static (SCRV1) or
	// dynamic (CRV1) challenge/response requirement; nil for a plain
	// username/password prompt.
	onAuthNeeded func(tunnelName string, challenge *AuthChallenge)
	// onActiveChange fires exactly on the transitions that matter for the
	// kill switch's OpenVPN whitelist — a tunnel reaching CONNECTED (active
	// true, its interface/remote are now known and ActiveRemotes will
	// include it) or being torn down (active false). Deliberately NOT
	// fired on every status update — onStatus/emitStatus also fires once a
	// second for bytecount, which would rebuild pf rules needlessly often.
	onActiveChange func(tunnelName string, active bool)
}

// NewManager constructs an OpenVPN Manager. binaryPath is the absolute path to
// the bundled openvpn executable; runtimeDir is a writable directory for
// per-tunnel runtime config, management sockets, and logs.
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

// runtime file paths for a tunnel.
func (m *Manager) configPath(name string) string { return filepath.Join(m.runtimeDir, name+".ovpn") }
func (m *Manager) sockPath(name string) string   { return filepath.Join(m.runtimeDir, name+".mgmt.sock") }
func (m *Manager) logPath(name string) string    { return filepath.Join(m.runtimeDir, name+".log") }

// Connect starts an OpenVPN tunnel from the given raw .ovpn content. It returns
// once the subprocess has been started and supervision goroutines are running —
// the actual CONNECTED transition (and any auth prompt) happens asynchronously
// and is reported via onStatus / onAuthNeeded.
func (m *Manager) Connect(name string, ovpnContent []byte) error {
	// name is interpolated directly into configPath/sockPath/logPath below
	// with no further sanitization — reject anything unsafe for filesystem
	// use here too, not just at the IPC handler layer, so this manager is
	// safe to call directly (e.g. from cmd/test) without relying on every
	// caller to have already validated the name.
	if err := storage.ValidateTunnelName(name); err != nil {
		return fmt.Errorf("invalid tunnel name: %w", err)
	}
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

	// 2. Remove any stale socket left by a previous crashed run.
	_ = os.Remove(sockPath)

	// 3. Write the user's .ovpn verbatim (no appended directives). Management
	// parameters are passed as CLI flags below so they cannot be overridden by
	// a malicious directive in the config file.
	if err := os.WriteFile(cfgPath, ovpnContent, 0600); err != nil {
		return fmt.Errorf("writing runtime config: %w", err)
	}

	// Resolve the remote server now, before the subprocess starts (see
	// resolveRemoteForKillSwitch), so the kill switch can whitelist this
	// tunnel's traffic once it's connected.
	remoteAddr, remoteProto := "", ""
	if cfg, perr := ParseOVPN(ovpnContent); perr == nil {
		remoteAddr, remoteProto = resolveRemoteForKillSwitch(cfg)
	}

	// 4. Start the openvpn subprocess. Management flags as CLI args take
	// precedence over any conflicting directives in the config file.
	//
	// --script-security 1 (not 2): level 0 blocks openvpn's OWN internal use
	// of /sbin/ifconfig and /sbin/route to configure the tun interface and
	// routes on macOS (that's what broke in v1.0.53), but level 1 permits
	// exactly those built-in system calls while still refusing to execute
	// ANY user-defined script (--up/--down/--route-up/etc). Since
	// ValidateOVPN already rejects configs containing those directives at
	// import time, level 1 costs us nothing functionally and closes off the
	// whole class of "script directive slipped past the validator" bugs as
	// a second, independent line of defense — level 2 would happily run a
	// user-defined script if one ever got past ValidateOVPN (as one
	// recently did: see normalizeDirective in config.go).
	//
	// --setenv IV_SSO webauth,crtext declares to the server that this client
	// can handle a text-based challenge-response or web-SSO redirect during
	// auth-user-pass. Some enterprise gateways gate their RADIUS/LDAP auth
	// plugin on this peer-info flag: without it, they fail auth outright
	// (AUTH_FAILED, no challenge ever offered) instead of attempting one.
	// Official clients (OpenVPN Connect, Tunnelblick) always set this
	// regardless of whether the server ends up using it.
	//
	// --auth-retry interact: without it, OpenVPN's core exits the process
	// outright on ANY auth failure — including the intermediate
	// "Verification Failed" that CARRIES a CRV1 dynamic challenge. The
	// management-notes.txt spec is explicit that this flag "must be in
	// effect so that the connection is restarted and credentials are
	// requested again" — that restart-and-reprompt is what lets us collect
	// the challenge response and feed it back via a fresh "Need 'Auth'"
	// prompt (see onMgmtDynamicChallenge/onMgmtAuthPrompt). As a side
	// effect this also makes a plain wrong-password re-prompt via the GUI
	// instead of silently killing the tunnel — a strictly better default
	// for a GUI-driven client (our own 10-minute per-prompt timeout in
	// onMgmtAuthPrompt still bounds how long any single retry can hang).
	cmd := exec.Command(m.binaryPath,
		"--config", cfgPath,
		"--management", sockPath, "unix",
		"--management-hold",
		"--management-query-passwords",
		"--script-security", "1",
		"--setenv", "IV_SSO", "webauth,crtext",
		"--auth-retry", "interact",
	)
	cmd.Dir = m.runtimeDir
	// Stdout is scanned for the negotiated cipher (see scanOutput) and
	// forwarded through slog at Debug level. Stderr is piped straight to
	// os.Stderr since openvpn's own diagnostics go through stdout — stderr
	// only ever carries the rare fatal-before-fork message.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("attaching openvpn stdout: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting openvpn: %w", err)
	}
	go m.scanOutput(name, stdout)

	e := &entry{
		cmd:     cmd,
		authCh:  make(chan authReply, 1),
		closeCh: make(chan struct{}),
		status: domain.ConnectionStatus{
			State:      domain.StateConnecting,
			TunnelName: name,
			Protocol:   domain.ProtocolOpenVPN,
		},
		remoteAddr:  remoteAddr,
		remoteProto: remoteProto,
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
		func(state, localIP, remoteAddr string) { m.onMgmtState(name, state, localIP, remoteAddr) },
		func(rx, tx int64) { m.onMgmtBytes(name, rx, tx) },
		func(sc *AuthChallenge) { m.onMgmtAuthPrompt(name, e, sc) },
		func(ch *AuthChallenge) { m.onMgmtDynamicChallenge(name, e, ch) },
		func() { /* readLoop done — handled below */ },
	)

	// Management connection ended → openvpn is shutting down or dead. Reap it.
	_ = e.cmd.Wait()
	slog.Info("ovpn: tunnel process exited", "tunnel", name)
	m.cleanup(name)
}

// scanOutput reads openvpn's stdout line by line, routing everything through
// slog at Debug level (so it only reaches disk/the log viewer when the user
// has actually turned on debug logging — the imported .ovpn profile's own
// `verb` setting is honored verbatim, and at higher verbosities OpenVPN logs
// per-packet diagnostics that scale with traffic, not a fixed interval)
// while also watching for the "Data Channel: cipher '...'" line that reveals
// the negotiated cipher, and the PUSH_REPLY line that carries server-pushed
// DNS — information the management interface itself never exposes.
func (m *Manager) scanOutput(name string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		slog.Debug("ovpn: "+line, "tunnel", name)
		if match := cipherLogRe.FindStringSubmatch(line); match != nil {
			m.setCipher(name, match[1])
		}
		if strings.Contains(line, "PUSH_REPLY") {
			m.applyPushedDNS(name, line)
		}
		if match := ifaceLogRe.FindStringSubmatch(line); match != nil {
			m.setInterfaceName(name, match[1])
		}
	}
}

// setInterfaceName records the OS tun/utun device name OpenVPN opened for
// this tunnel and emits the status. See ifaceLogRe for why this has to be
// scraped from a log line instead of read structurally.
func (m *Manager) setInterfaceName(name, ifaceName string) {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	if ok {
		e.status.InterfaceName = ifaceName
	}
	m.mu.Unlock()
	if ok {
		m.emitStatus(name)
	}
}

// applyPushedDNS extracts dhcp-option DNS/DOMAIN entries from a PUSH_REPLY
// log line and applies them via netMgr, mirroring how WireGuard's `DNS = ...`
// directive is applied. No-op if the line carries no dhcp-option entries.
func (m *Manager) applyPushedDNS(name, pushReplyLine string) {
	matches := dhcpOptionRe.FindAllStringSubmatch(pushReplyLine, -1)
	if len(matches) == 0 || m.netMgr == nil {
		return
	}
	entries := make([]string, 0, len(matches))
	for _, mm := range matches {
		entries = append(entries, strings.TrimSpace(mm[2]))
	}
	if err := m.netMgr.SetDNS(name, entries); err != nil {
		slog.Warn("ovpn: failed to apply server-pushed DNS", "tunnel", name, "entries", entries, "error", err)
		return
	}
	// Keep only actual server IPs for status reporting — entries also
	// contains DOMAIN search-suffix values (e.g. "all-service.local"),
	// which SetDNS legitimately needs but aren't DNS servers themselves and
	// would corrupt an "is this resolver one of ours" comparison (like the
	// DNS leak test) if included.
	var dnsIPs []string
	for _, e := range entries {
		if net.ParseIP(e) != nil {
			dnsIPs = append(dnsIPs, e)
		}
	}

	m.mu.Lock()
	e, ok := m.tunnels[name]
	if ok {
		e.dnsApplied = true
		e.status.DNSServers = dnsIPs
	}
	m.mu.Unlock()
	if !ok {
		// The tunnel died (cleanup already ran, dnsApplied never got set)
		// while SetDNS — a slow, multi-second networksetup fan-out — was
		// still in flight. Nobody will ever call RestoreDNS for this
		// tunnel now, so do it ourselves or the pushed DNS is stuck
		// overriding the system resolver permanently.
		_ = m.netMgr.RestoreDNS(name)
		return
	}
	slog.Info("ovpn: applied server-pushed DNS", "tunnel", name, "entries", entries)
}

// setCipher records the negotiated data-channel cipher and emits the status.
func (m *Manager) setCipher(name, cipher string) {
	m.mu.Lock()
	e, ok := m.tunnels[name]
	if ok {
		e.status.Cipher = cipher
	}
	m.mu.Unlock()
	if ok {
		m.emitStatus(name)
	}
}

// onMgmtState maps an OpenVPN management state string to a domain state.
// localIP is the tunnel-assigned client address; only non-empty on
// CONNECTED. remoteAddr is the actual remote server OpenVPN is CURRENTLY
// connected to (also only non-empty on CONNECTED) — see readLoop's doc
// comment. Updating entry.remoteAddr from this LIVE value (rather than only
// ever trusting the one resolved once at Connect time) is what lets the
// kill switch's whitelist survive OpenVPN's own internal reconnect to a
// different remote/round-robin IP; see resolveRemoteForKillSwitch's doc
// comment for the gap this closes.
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
	case "RECONNECTING":
		e.status.State = domain.StateConnecting
	default:
		// CONNECTING, WAIT, AUTH, GET_CONFIG, ASSIGN_IP, ADD_ROUTES, etc.
		if e.status.State != domain.StateConnected {
			e.status.State = domain.StateConnecting
		}
	}
	nowConnected := e.status.State == domain.StateConnected
	m.mu.Unlock()
	slog.Debug("ovpn: state change", "tunnel", name, "state", state)
	m.emitStatus(name)
	// Fire only on the actual CONNECTED transition (not every status
	// update — bytecount alone would otherwise trigger this every second
	// via emitStatus) so the kill switch can pick up this tunnel's
	// now-known interface/remote. See onActiveChange's doc comment.
	if nowConnected && !wasConnected && m.onActiveChange != nil {
		m.onActiveChange(name, true)
	}
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

// onMgmtAuthPrompt is invoked when the server requests credentials via a
// "Need 'Auth'" prompt. sc is non-nil if THIS prompt carries a static
// (SCRV1) challenge suffix. It signals the GUI and blocks (in this
// goroutine — the management read loop) until FeedCredentials supplies a
// reply or a timeout elapses.
//
// If a dynamic (CRV1) challenge is already pending for this tunnel (see
// onMgmtDynamicChallenge), this prompt is the auth-retry reconnect it
// triggered — the GUI was already notified when the challenge first
// arrived, so it is NOT notified again here (that would pop a second,
// resetting prompt on top of one the user may already be filling in).
func (m *Manager) onMgmtAuthPrompt(name string, e *entry, sc *AuthChallenge) {
	slog.Info("ovpn: server requesting credentials", "tunnel", name)

	m.mu.Lock()
	pending := e.pendingChallenge
	m.mu.Unlock()

	challenge := sc
	notifyGUI := true
	if challenge == nil && pending != nil {
		challenge = pending
		notifyGUI = false
	}

	if notifyGUI {
		// Drain any stale credential left by a previous timed-out prompt. A
		// TOTP code from an earlier attempt would be expired anyway, and
		// silently reusing it would fail auth without showing the GUI
		// prompt. Skipped for a CRV1 retry (notifyGUI false): the user may
		// have already answered the challenge before this reconnect's
		// prompt even arrived, and draining here would discard that reply.
		select {
		case <-e.authCh:
			slog.Debug("ovpn: drained stale credential from previous prompt", "tunnel", name)
		default:
		}
		if m.onAuthNeeded != nil {
			m.onAuthNeeded(name, challenge)
		}
	}

	select {
	case reply := <-e.authCh:
		m.mu.Lock()
		mgmt := e.mgmt
		e.pendingChallenge = nil
		lastUsername := e.lastUsername
		m.mu.Unlock()
		if mgmt == nil {
			slog.Warn("ovpn: management gone before credentials arrived", "tunnel", name)
			return
		}

		username, password := reply.username, reply.password
		switch {
		case challenge != nil && challenge.Kind == ChallengeDynamic:
			// The frontend showed a response-only form (no username field)
			// — reuse the username that was already accepted at the base
			// login, and wrap the response per the CRV1 wire format.
			username = lastUsername
			password = fmt.Sprintf("CRV1::%s::%s", challenge.StateID, reply.response)
		case challenge != nil && challenge.Kind == ChallengeStatic:
			password = combineStaticChallenge(challenge, reply.password, reply.response)
		}
		if username != "" {
			m.mu.Lock()
			e.lastUsername = username
			m.mu.Unlock()
		}

		// Username at Debug, not Info — it's credential-adjacent PII that
		// would otherwise land in the default-level log stream (and
		// Console.app, since the helper's log level defaults to Info) on
		// every single auth attempt. The password is correctly never logged.
		slog.Debug("ovpn: sending credentials to management socket", "tunnel", name, "username", username, "challenge_kind", challengeKindOf(challenge))
		if err := mgmt.sendCredentials(username, password); err != nil {
			slog.Error("ovpn: sending credentials failed", "tunnel", name, "error", err)
			m.setError(name, fmt.Sprintf("sending credentials failed: %v", err))
		}
	case <-e.closeCh:
		// Disconnect was called while we were waiting — e.g. the user
		// cancelled the auth modal. Return without sending anything; the
		// process is already being torn down (see Disconnect), and
		// supervise's cmd.Wait() will reap it and run cleanup() once the
		// management connection actually closes. Without this case, this
		// goroutine (and thus readLoop) would stay blocked here for up to
		// the full 10-minute timeout below even though nothing is left to
		// wait for, leaving the tunnel showing "connecting" the whole time.
		slog.Info("ovpn: tunnel disconnected while awaiting credentials", "tunnel", name)
		return
	case <-time.After(10 * time.Minute):
		slog.Warn("ovpn: timed out waiting for credentials", "tunnel", name)
		m.setError(name, "timed out waiting for credentials")
		m.Disconnect(name)
	}
}

// onMgmtDynamicChallenge is invoked when the server rejects the base
// credentials with a CRV1 dynamic-challenge payload (2FA required). It
// notifies the GUI and stores the challenge for onMgmtAuthPrompt to answer
// once OpenVPN's auth-retry brings a fresh "Need 'Auth'" prompt — it does
// NOT block here, unlike onMgmtAuthPrompt, so the read loop keeps
// processing state/bytecount lines (and the eventual retry prompt) while
// the user is entering their response.
func (m *Manager) onMgmtDynamicChallenge(name string, e *entry, ch *AuthChallenge) {
	slog.Info("ovpn: server issued a dynamic challenge, awaiting response", "tunnel", name)
	m.mu.Lock()
	e.pendingChallenge = ch
	m.mu.Unlock()
	// Drain any stale reply left over from an earlier, already-resolved
	// prompt before waiting for a fresh one.
	select {
	case <-e.authCh:
	default:
	}
	if m.onAuthNeeded != nil {
		m.onAuthNeeded(name, ch)
	}
}

// combineStaticChallenge formats a password + challenge response per the
// SCRV1 wire protocol's Concat flag (see AuthChallenge.Concat / FORMAT bit).
func combineStaticChallenge(ch *AuthChallenge, password, response string) string {
	if ch.Concat {
		return password + response
	}
	return fmt.Sprintf("SCRV1:%s:%s",
		base64.StdEncoding.EncodeToString([]byte(password)),
		base64.StdEncoding.EncodeToString([]byte(response)))
}

// challengeKindOf returns a log-safe label for a possibly-nil challenge.
func challengeKindOf(ch *AuthChallenge) ChallengeKind {
	if ch == nil {
		return ChallengeNone
	}
	return ch.Kind
}

// FeedCredentials delivers a reply for a tunnel waiting on an auth prompt.
// fullPassword must already be basePassword + totpCode (combined by the
// caller) for a plain prompt. response carries the user's answer to a
// challenge/response prompt: for a dynamic (CRV1) prompt it's the ENTIRE
// reply (fullPassword is ignored); for a static (SCRV1) prompt it's paired
// with fullPassword. Ignored for a plain prompt.
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

	// Unblock onMgmtAuthPrompt if it's currently waiting on user input —
	// see closeCh's doc comment on entry.
	e.closeOnce.Do(func() { close(e.closeCh) })

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

// ActiveRemotes returns the resolved remote endpoint for every connected
// tunnel that has one — i.e. DNS resolution at Connect time succeeded (see
// resolveRemoteForKillSwitch) and the tunnel has reached CONNECTED so its
// interface name is known (see setInterfaceName). Used by the kill switch to
// whitelist OpenVPN traffic alongside WireGuard's.
func (m *Manager) ActiveRemotes() []RemoteEndpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []RemoteEndpoint
	for name, e := range m.tunnels {
		if e.status.State != domain.StateConnected || e.remoteAddr == "" || e.status.InterfaceName == "" {
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
	wasConnected := ok && e.status.State == domain.StateConnected
	delete(m.tunnels, name)
	m.mu.Unlock()

	// Only worth a kill-switch rebuild if this tunnel was actually
	// CONNECTED (and therefore possibly included in its whitelist) before
	// being torn down — e.g. a tunnel that failed during the auth prompt
	// never got that far, so there's nothing to remove.
	if wasConnected && m.onActiveChange != nil {
		m.onActiveChange(name, false)
	}

	if ok && e.mgmt != nil {
		_ = e.mgmt.close()
	}
	if ok && e.dnsApplied && m.netMgr != nil {
		if err := m.netMgr.RestoreDNS(name); err != nil {
			slog.Warn("ovpn: failed to restore DNS", "tunnel", name, "error", err)
		}
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
