// Package tunnel orchestrates WireGuard tunnel lifecycle.
//
// The package is split so each file has a single reason to change:
//   - manager.go         (this file)   — Manager struct, state machine, Connect/Disconnect/Status facade
//   - connect_phases.go                — the step-by-step Connect / Disconnect phases and rollback
//   - status.go                        — status type alias + GetStatus query (wgctrl)
//   - engine.go                        — wireguard-go + wgctrl TUN wiring
//   - conflict.go                      — existing-interface conflict detection
//   - recovery.go                      — crash recovery state file
package tunnel

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/network"
)

// tunnelEntry is one tunnel's state machine, engine, config and its own
// NetworkManager.
type tunnelEntry struct {
	state       domain.State
	engine      *Engine
	cfg         *domain.WireGuardConfig
	connectedAt time.Time
	netMgr      network.NetworkManager // per-tunnel network state (routes, DNS, monitor)
}

// Manager orchestrates the tunnel lifecycle using a small state machine
// per tunnel.
//
//	disconnected ──Connect──▶ connecting ──phases ok──▶ connected
//	                                    ──phases err─▶ disconnected
//	connected    ──Disconnect──▶ disconnecting ──▶ disconnected
//
// Manager.mu is held ONLY for state reads/writes, NEVER during the slow
// phase operations (ifconfig, route, networksetup).
// That keeps Status() / IsConnected() / ActiveTunnel() non-blocking even
// while a long-running Connect or Disconnect is in flight.
type Manager struct {
	mu sync.Mutex

	tunnels map[string]*tunnelEntry // keyed by tunnel name

	dataDir string

	// pinInterface is the current -ifscope setting. Stored on Manager so
	// it can be propagated to each newly-created per-tunnel NetworkManager.
	pinInterface bool

	// netMgrFactory creates a fresh NetworkManager for each tunnel.
	// Defaults to network.NewPlatformManager. Overridable in tests.
	netMgrFactory func() network.NetworkManager

	// engineFactory creates the WireGuard engine. Defaults to NewEngine.
	// Overridable in tests to avoid requiring root / TUN device access.
	engineFactory func(cfg *domain.WireGuardConfig) (*Engine, error)

	// onEngineDied is called (outside m.mu) after a connected tunnel's
	// engine dies on its own — see Engine.Died's doc comment — and this
	// Manager has finished tearing down its now-stale routes/DNS/state.
	// Set via SetOnEngineDied; wired by the helper to the reconnect
	// monitor so auto-reconnect-enabled tunnels recover instead of
	// silently staying disconnected.
	onEngineDied func(name string)
}

// SetOnEngineDied registers a callback invoked when a connected tunnel's
// engine dies unexpectedly (wireguard-go tearing itself down after a fatal
// TUN error, rather than a caller-initiated Disconnect). Not safe to call
// concurrently with Connect on the same Manager instance in production —
// call once during helper startup, before any tunnels connect.
func (m *Manager) SetOnEngineDied(fn func(name string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEngineDied = fn
}

// Additional transient states used internally. Exposed on the wire as the
// closest public state (connecting/disconnecting both surface as
// "connecting" since the GUI treats them the same way).
const (
	stateDisconnecting domain.State = "disconnecting"
)

// NewManager creates a tunnel manager. Each tunnel gets its own
// NetworkManager instance created via netMgrFactory, so one tunnel's
// route/DNS cleanup cannot affect another.
func NewManager(dataDir string) *Manager {
	return &Manager{
		dataDir:       dataDir,
		tunnels:       make(map[string]*tunnelEntry),
		netMgrFactory: func() network.NetworkManager { return network.NewPlatformManager() },
		engineFactory: NewEngine,
	}
}

// getOrCreateEntry returns the entry for a tunnel, creating a disconnected
// one if it doesn't exist. Caller MUST hold m.mu.
func (m *Manager) getOrCreateEntry(name string) *tunnelEntry {
	e, ok := m.tunnels[name]
	if !ok {
		e = &tunnelEntry{state: domain.StateDisconnected}
		m.tunnels[name] = e
	}
	return e
}

// removeEntry deletes a tunnel entry from the map. Caller MUST hold m.mu.
func (m *Manager) removeEntry(name string) {
	delete(m.tunnels, name)
}

// Connect establishes a WireGuard tunnel. Runs the expensive phase work
// WITHOUT holding m.mu, so Status / IsConnected / ActiveTunnel stay
// responsive for the duration.
//
// Multiple tunnels can be connected simultaneously. Only rejected if THIS
// specific tunnel name is already connected or a transition is in progress.
func (m *Manager) Connect(cfg *domain.WireGuardConfig) error {
	name := cfg.Name

	// --- Phase 1: claim the connecting slot under the lock ---
	m.mu.Lock()
	if existing, ok := m.tunnels[name]; ok {
		switch existing.state {
		case domain.StateConnected:
			m.mu.Unlock()
			return newTunnelError(ErrAlreadyConnected, fmt.Sprintf("tunnel %q is already connected", name), nil)
		case domain.StateConnecting, stateDisconnecting:
			m.mu.Unlock()
			return newTunnelError(ErrTransitionInProgress, fmt.Sprintf("tunnel %q: another transition is in progress", name), nil)
		}
	}
	// Reject if the new config is full-tunnel and any existing connected tunnel
	// is also full-tunnel — two 0.0.0.0/0 routes conflict on the route table.
	if cfg.IsFullTunnel() {
		for otherName, other := range m.tunnels {
			if otherName != name && other.state == domain.StateConnected && other.cfg != nil && other.cfg.IsFullTunnel() {
				m.mu.Unlock()
				return newTunnelError(ErrFullTunnelConflict,
					fmt.Sprintf("cannot connect full-tunnel %q: tunnel %q already routes all traffic (0.0.0.0/0)", name, otherName), nil)
			}
		}
	}

	// Create the entry only now that the connect is accepted, so a rejected
	// connect leaves no nameless Disconnected entry behind. The config is
	// stashed early so Status() can show "connecting <name>".
	entry := m.getOrCreateEntry(name)
	entry.cfg = cfg
	entry.state = domain.StateConnecting

	// Create a per-tunnel NetworkManager so this tunnel's routes, DNS
	// snapshot, and route monitor are independent of other tunnels.
	netMgr := m.netMgrFactory()
	if m.pinInterface {
		if dm, ok := netMgr.(interface{ SetPinInterface(bool) }); ok {
			dm.SetPinInterface(true)
		}
	}
	entry.netMgr = netMgr
	m.mu.Unlock()

	// --- Phase 2: run the slow operations WITHOUT holding the lock ---
	engine, err := m.connectPhases(cfg, netMgr)

	// --- Phase 3: commit final state under the lock ---
	m.mu.Lock()
	entry = m.getOrCreateEntry(name) // re-fetch under lock
	if err != nil {
		// Phases failed — roll back to disconnected. connectPhases has
		// already cleaned up its partial network state via its internal
		// rollback helper.
		m.removeEntry(name)
		m.mu.Unlock()
		return err
	}
	// Safety net: DisconnectTunnel never mutates a connecting entry and
	// connects are serialized upstream, so this should be unreachable. The
	// slow cleanup runs outside the lock.
	if entry.state != domain.StateConnecting {
		m.mu.Unlock()
		_ = netMgr.Cleanup(engine.InterfaceName())
		engine.Close()
		_ = ClearActiveState(m.dataDir, name)
		m.mu.Lock()
		m.removeEntry(name)
		m.mu.Unlock()
		return newTunnelError(ErrStateCorrupt, "connect aborted: state changed during setup", nil)
	}
	entry.engine = engine
	entry.connectedAt = time.Now()
	entry.state = domain.StateConnected
	m.mu.Unlock()
	go m.watchEngineDeath(name, engine)
	return nil
}

// watchEngineDeath waits for the engine's device loop to exit, then checks
// whether it died on its own. Not a select on both channels: both may be
// ready and select would pick randomly; died is closed before stopped.
func (m *Manager) watchEngineDeath(name string, engine *Engine) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("watchEngineDeath panic (recovered)",
				"panic", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()))
		}
	}()
	<-engine.Stopped()
	select {
	case <-engine.Died():
		m.handleEngineDied(name, engine)
	default:
		// Normal, caller-initiated Close() — nothing to do.
	}
}

// handleEngineDied tears down a tunnel whose engine died on its own. Mirrors
// DisconnectTunnel's snapshot-then-unlock-then-teardown structure.
func (m *Manager) handleEngineDied(name string, engine *Engine) {
	m.mu.Lock()
	entry, ok := m.tunnels[name]
	// A stale watcher from a prior engine must not tear down a newer one.
	if !ok || entry.engine != engine || entry.state != domain.StateConnected {
		m.mu.Unlock()
		return
	}
	slog.Warn("tunnel engine died unexpectedly, tearing down stale state", "tunnel", name)
	cfg := entry.cfg
	netMgr := entry.netMgr
	entry.state = stateDisconnecting
	m.mu.Unlock()

	m.disconnectPhases(cfg, engine, netMgr)

	m.mu.Lock()
	m.removeEntry(name)
	onDied := m.onEngineDied
	m.mu.Unlock()

	if onDied != nil {
		onDied(name)
	}
}

// DisconnectTunnel tears down a specific tunnel by name. Like Connect, runs
// the slow teardown work outside the lock.
func (m *Manager) DisconnectTunnel(name string) error {
	// --- Phase 1: wait for any in-flight transition on THIS tunnel to settle ---
	deadline := time.Now().Add(10 * time.Second)
	for {
		m.mu.Lock()
		entry, ok := m.tunnels[name]
		if !ok {
			m.mu.Unlock()
			return newTunnelError(ErrNotConnected, fmt.Sprintf("tunnel %q is not connected", name), nil)
		}
		if entry.state != domain.StateConnecting && entry.state != stateDisconnecting {
			break // lock still held, state is stable
		}
		m.mu.Unlock()
		if time.Now().After(deadline) {
			return newTunnelError(ErrTimeout, fmt.Sprintf("disconnect timeout for tunnel %q: transition in progress", name), nil)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// m.mu held here, state is Connected / Disconnected / Error.
	entry := m.tunnels[name]
	if entry.state != domain.StateConnected {
		m.mu.Unlock()
		return newTunnelError(ErrNotConnected, fmt.Sprintf("tunnel %q is not connected", name), nil)
	}
	// Snapshot the handles we need outside the lock.
	engine := entry.engine
	cfg := entry.cfg
	netMgr := entry.netMgr
	if engine == nil {
		m.removeEntry(name)
		m.mu.Unlock()
		return newTunnelError(ErrStateCorrupt, fmt.Sprintf("engine is nil for tunnel %q despite connected state", name), nil)
	}
	entry.state = stateDisconnecting
	m.mu.Unlock()

	// --- Phase 2: slow teardown outside the lock ---
	m.disconnectPhases(cfg, engine, netMgr)

	// --- Phase 3: commit final state ---
	m.mu.Lock()
	m.removeEntry(name)
	m.mu.Unlock()
	return nil
}

// DisconnectAll tears down all active tunnels, including those still in the
// connecting state. DisconnectTunnel internally waits for connecting tunnels
// to settle before tearing them down. Used during shutdown.
func (m *Manager) DisconnectAll() {
	m.mu.Lock()
	var names []string
	for n, e := range m.tunnels {
		if e.state == domain.StateConnected || e.state == domain.StateConnecting {
			names = append(names, n)
		}
	}
	m.mu.Unlock()

	for _, name := range names {
		if err := m.DisconnectTunnel(name); err != nil {
			slog.Warn("DisconnectAll: failed to disconnect tunnel", "tunnel", name, "error", err)
		}
	}
}

// entrySnap is the part of a tunnelEntry needed to build its status
// outside m.mu (GetStatus talks to wgctrl).
type entrySnap struct {
	state       domain.State
	engine      *Engine
	connectedAt time.Time
	name        string
}

func snapOf(e *tunnelEntry) entrySnap {
	s := entrySnap{state: e.state, engine: e.engine, connectedAt: e.connectedAt}
	if e.cfg != nil {
		s.name = e.cfg.Name
	}
	return s
}

// status maps an entry to its wire status. Connecting and disconnecting both
// surface as "connecting".
func (s entrySnap) status() *ConnectionStatus {
	switch s.state {
	case domain.StateConnecting, stateDisconnecting:
		return &ConnectionStatus{State: domain.StateConnecting, TunnelName: s.name}
	case domain.StateConnected:
		if s.engine == nil {
			break
		}
		st, err := GetStatus(s.engine.InterfaceName(), s.name, s.connectedAt)
		if err != nil {
			slog.Debug("failed to get tunnel status", "tunnel", s.name, "error", err)
			return &ConnectionStatus{State: domain.StateError, TunnelName: s.name}
		}
		return st
	case domain.StateError:
		return &ConnectionStatus{State: domain.StateError, TunnelName: s.name}
	}
	return &ConnectionStatus{State: domain.StateDisconnected, TunnelName: s.name}
}

// Status returns the status of the "primary" tunnel (first connected, else
// first transitioning, else first errored, by name), with ActiveTunnels
// listing every active tunnel.
func (m *Manager) Status() *ConnectionStatus {
	m.mu.Lock()
	active := m.activeTunnelNamesLocked()
	var primary *tunnelEntry
	for _, want := range []func(domain.State) bool{
		func(st domain.State) bool { return st == domain.StateConnected },
		func(st domain.State) bool { return st == domain.StateConnecting || st == stateDisconnecting },
		func(st domain.State) bool { return st == domain.StateError },
	} {
		for _, name := range m.sortedNamesLocked() {
			if e := m.tunnels[name]; want(e.state) {
				primary = e
				break
			}
		}
		if primary != nil {
			break
		}
	}
	if primary == nil {
		m.mu.Unlock()
		return &ConnectionStatus{State: domain.StateDisconnected, ActiveTunnels: active}
	}
	snap := snapOf(primary)
	m.mu.Unlock()

	st := snap.status()
	st.ActiveTunnels = active
	return st
}

// AllStatuses returns the status of every tunnel that has an entry.
func (m *Manager) AllStatuses() []*ConnectionStatus {
	m.mu.Lock()
	snaps := make([]entrySnap, 0, len(m.tunnels))
	for _, name := range m.sortedNamesLocked() {
		snaps = append(snaps, snapOf(m.tunnels[name]))
	}
	m.mu.Unlock()

	out := make([]*ConnectionStatus, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, s.status())
	}
	return out
}

// TunnelInfo describes a connected tunnel for the helper's firewall policy.
type TunnelInfo struct {
	Name          string
	InterfaceName string
	Endpoints     []string // resolved "ip:port" of every peer
	DNS           []string // configured DNS entries (servers and search domains)
}

// ConnectedTunnels returns every fully connected tunnel, sorted by name.
func (m *Manager) ConnectedTunnels() []TunnelInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []TunnelInfo
	for _, name := range m.sortedNamesLocked() {
		e := m.tunnels[name]
		if e.state != domain.StateConnected || e.engine == nil || e.cfg == nil {
			continue
		}
		out = append(out, TunnelInfo{
			Name:          name,
			InterfaceName: e.engine.InterfaceName(),
			Endpoints:     e.engine.ResolvedEndpoints(),
			DNS:           append([]string(nil), e.cfg.Interface.DNS...),
		})
	}
	return out
}

// IsConnected returns true if ANY tunnel is fully established.
func (m *Manager) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.tunnels {
		if e.state == domain.StateConnected {
			return true
		}
	}
	return false
}

// IsTunnelConnected returns true if the named tunnel is fully established.
func (m *Manager) IsTunnelConnected(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.tunnels[name]
	return ok && e.state == domain.StateConnected
}

// ActiveTunnel returns the name of the first connected (or connecting)
// tunnel, or "" if none. Kept for backward compatibility — callers that
// only support a single tunnel can use this.
func (m *Manager) ActiveTunnel() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := m.activeTunnelNamesLocked()
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// ActiveTunnels returns the names of all connected or connecting tunnels,
// sorted alphabetically for deterministic ordering.
func (m *Manager) ActiveTunnels() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeTunnelNamesLocked()
}

// activeTunnelNamesLocked returns sorted names of all active tunnels.
// Caller MUST hold m.mu.
func (m *Manager) activeTunnelNamesLocked() []string {
	var names []string
	for _, name := range m.sortedNamesLocked() {
		switch m.tunnels[name].state {
		case domain.StateConnected, domain.StateConnecting, stateDisconnecting:
			names = append(names, name)
		}
	}
	return names
}

// sortedNamesLocked returns every entry's name, sorted. Caller MUST hold m.mu.
func (m *Manager) sortedNamesLocked() []string {
	names := make([]string, 0, len(m.tunnels))
	for name := range m.tunnels {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// SetPinInterface enables or disables -ifscope bypass route pinning on macOS.
// The setting is stored on the Manager and propagated to every active
// tunnel's NetworkManager, as well as any future tunnels created via Connect.
func (m *Manager) SetPinInterface(enabled bool) {
	m.mu.Lock()
	m.pinInterface = enabled
	// Propagate to all active per-tunnel NetworkManagers.
	for _, e := range m.tunnels {
		if e.netMgr != nil {
			if dm, ok := e.netMgr.(interface{ SetPinInterface(bool) }); ok {
				dm.SetPinInterface(enabled)
			}
		}
	}
	m.mu.Unlock()
}
