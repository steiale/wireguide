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

// tunnelEntry holds the state for a single tunnel within the multi-tunnel
// manager. Each entry has its own state machine, engine, config, connected
// timestamp, and per-tunnel NetworkManager instance.
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
	entry := m.getOrCreateEntry(name)
	switch entry.state {
	case domain.StateConnected:
		m.mu.Unlock()
		return newTunnelError(ErrAlreadyConnected, fmt.Sprintf("tunnel %q is already connected", name), nil)
	case domain.StateConnecting, stateDisconnecting:
		m.mu.Unlock()
		return newTunnelError(ErrTransitionInProgress, fmt.Sprintf("tunnel %q: another transition is in progress", name), nil)
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

	// Stash the tunnel config early so Status() can show "connecting <name>"
	// while the phases are running.
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
	// Re-validate state: a Disconnect may have landed while we were outside
	// the lock. If so, discard the engine we just created.
	//
	// In practice DisconnectTunnel POLLS until a tunnel leaves
	// StateConnecting before touching it (it never mutates a connecting
	// entry directly) and Connect calls are already serialized upstream
	// (helper.connectMu), so this branch should be unreachable today — but
	// it's cheap to check and kept as a safety net against a future change
	// to either of those invariants. It does NOT hold m.mu across the slow
	// network cleanup calls below (a previous version did, via this
	// function's now-removed top-level `defer m.mu.Unlock()`) — doing so
	// would block every other Status()/IsConnected() caller for as long as
	// RemoveRoutes/RestoreDNS/Cleanup's networksetup/route fan-out takes.
	if entry.state != domain.StateConnecting {
		m.mu.Unlock()
		// Clean up the network state that connectPhases just installed —
		// outside the lock, see comment above.
		netMgr.RemoveRoutes(engine.InterfaceName(), nil, cfg.IsFullTunnel())
		netMgr.RestoreDNS(engine.InterfaceName())
		netMgr.Cleanup(engine.InterfaceName())
		engine.Close()
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

// watchEngineDeath blocks until the engine's device loop exits for ANY
// reason (Stopped(), which — unlike Died() — always fires, including on a
// normal Close()) and then checks whether that exit was an unexpected death.
//
// This deliberately does NOT `select` on Died() and Stopped() together: both
// channels can be closed by the time this goroutine gets scheduled, and a
// select with two simultaneously-ready cases picks between them uniformly at
// RANDOM — a 50% chance of silently skipping handleEngineDied on a genuine
// death. Waiting on Stopped() alone and then checking Died() with a
// non-blocking select is race-free instead: engine.go's watcher closes died
// (if applicable) strictly before it closes stopped, in that order, in the
// same goroutine — so by the time Stopped() has been observed as closed,
// Died()'s closed-or-not state is already decided and visible, no race.
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
	// entry.engine != engine guards against a stale watcher from a PRIOR
	// engine instance for this tunnel name (e.g. it died, this handler is
	// still queued behind m.mu, and meanwhile the tunnel was manually
	// reconnected with a fresh engine before we got the lock) — don't tear
	// down the new, healthy connection.
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

// Disconnect tears down the first connected tunnel. Kept for backward
// compatibility with callers that only support a single tunnel (reconnect
// monitor, tray, etc.). Use DisconnectTunnel for named disconnects.
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	var name string
	for n, e := range m.tunnels {
		if e.state == domain.StateConnected || e.state == domain.StateConnecting {
			name = n
			break
		}
	}
	m.mu.Unlock()
	if name == "" {
		return newTunnelError(ErrNotConnected, "no tunnel is connected", nil)
	}
	return m.DisconnectTunnel(name)
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

// Status returns the status of the first connected (or connecting) tunnel.
// For backward compatibility with single-tunnel callers. The returned
// ConnectionStatus includes ActiveTunnels listing all active tunnel names.
func (m *Manager) Status() *ConnectionStatus {
	m.mu.Lock()
	// Find the "primary" tunnel (first connected, or first connecting).
	var primary *tunnelEntry
	var primaryName string
	activeTunnels := m.activeTunnelNamesLocked()
	for _, name := range activeTunnels {
		e := m.tunnels[name]
		if e.state == domain.StateConnected {
			primary = e
			primaryName = name
			break
		}
	}
	if primary == nil {
		for _, name := range activeTunnels {
			e := m.tunnels[name]
			if e.state == domain.StateConnecting || e.state == stateDisconnecting {
				primary = e
				primaryName = name
				break
			}
		}
	}
	// Check for error state tunnels if nothing else found.
	if primary == nil {
		for name, e := range m.tunnels {
			if e.state == domain.StateError {
				primary = e
				primaryName = name
				break
			}
		}
	}

	if primary == nil {
		m.mu.Unlock()
		return &ConnectionStatus{
			State:         domain.StateDisconnected,
			ActiveTunnels: activeTunnels,
		}
	}

	state := primary.state
	engine := primary.engine
	connectedAt := primary.connectedAt
	_ = primaryName // used for logging only
	cfgName := ""
	if primary.cfg != nil {
		cfgName = primary.cfg.Name
	}
	m.mu.Unlock()

	switch state {
	case domain.StateConnecting, stateDisconnecting:
		return &ConnectionStatus{
			State:         domain.StateConnecting,
			TunnelName:    cfgName,
			ActiveTunnels: activeTunnels,
		}
	case domain.StateDisconnected:
		return &ConnectionStatus{
			State:         domain.StateDisconnected,
			ActiveTunnels: activeTunnels,
		}
	case domain.StateError:
		return &ConnectionStatus{
			State:         domain.StateError,
			TunnelName:    cfgName,
			ActiveTunnels: activeTunnels,
		}
	}

	// StateConnected — talk to wgctrl without holding m.mu.
	if engine == nil {
		return &ConnectionStatus{
			State:         domain.StateDisconnected,
			ActiveTunnels: activeTunnels,
		}
	}
	status, err := GetStatus(engine.InterfaceName(), cfgName, connectedAt)
	if err != nil {
		slog.Warn("failed to get status", "error", err)
		return &ConnectionStatus{
			State:         domain.StateError,
			TunnelName:    cfgName,
			ActiveTunnels: activeTunnels,
		}
	}
	status.ActiveTunnels = activeTunnels
	return status
}

// StatusFor returns the status of a specific tunnel by name.
func (m *Manager) StatusFor(name string) *ConnectionStatus {
	m.mu.Lock()
	entry, ok := m.tunnels[name]
	if !ok {
		m.mu.Unlock()
		return &ConnectionStatus{State: domain.StateDisconnected, TunnelName: name}
	}
	state := entry.state
	engine := entry.engine
	connectedAt := entry.connectedAt
	cfgName := ""
	if entry.cfg != nil {
		cfgName = entry.cfg.Name
	}
	m.mu.Unlock()

	switch state {
	case domain.StateConnecting, stateDisconnecting:
		return &ConnectionStatus{State: domain.StateConnecting, TunnelName: cfgName}
	case domain.StateDisconnected:
		return &ConnectionStatus{State: domain.StateDisconnected, TunnelName: cfgName}
	case domain.StateError:
		return &ConnectionStatus{State: domain.StateError, TunnelName: cfgName}
	}

	if engine == nil {
		return &ConnectionStatus{State: domain.StateDisconnected, TunnelName: cfgName}
	}
	status, err := GetStatus(engine.InterfaceName(), cfgName, connectedAt)
	if err != nil {
		return &ConnectionStatus{State: domain.StateError, TunnelName: cfgName}
	}
	return status
}

// AllStatuses returns the status of every tunnel that has an entry.
func (m *Manager) AllStatuses() []*ConnectionStatus {
	m.mu.Lock()
	type snap struct {
		name        string
		state       domain.State
		engine      *Engine
		connectedAt time.Time
		cfgName     string
	}
	var snaps []snap
	for name, e := range m.tunnels {
		cfgName := ""
		if e.cfg != nil {
			cfgName = e.cfg.Name
		}
		snaps = append(snaps, snap{name, e.state, e.engine, e.connectedAt, cfgName})
	}
	m.mu.Unlock()

	var out []*ConnectionStatus
	for _, s := range snaps {
		switch s.state {
		case domain.StateConnecting, stateDisconnecting:
			out = append(out, &ConnectionStatus{State: domain.StateConnecting, TunnelName: s.cfgName})
		case domain.StateDisconnected:
			out = append(out, &ConnectionStatus{State: domain.StateDisconnected, TunnelName: s.cfgName})
		case domain.StateError:
			out = append(out, &ConnectionStatus{State: domain.StateError, TunnelName: s.cfgName})
		case domain.StateConnected:
			if s.engine == nil {
				out = append(out, &ConnectionStatus{State: domain.StateDisconnected, TunnelName: s.cfgName})
				continue
			}
			st, err := GetStatus(s.engine.InterfaceName(), s.cfgName, s.connectedAt)
			if err != nil {
				out = append(out, &ConnectionStatus{State: domain.StateError, TunnelName: s.cfgName})
			} else {
				out = append(out, st)
			}
		}
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

// ResolvedEndpointIPs returns the union of pre-resolved endpoint IP addresses
// from all active engines. Returns nil if no tunnel is connected.
func (m *Manager) ResolvedEndpointIPs() []string {
	m.mu.Lock()
	var engines []*Engine
	for _, e := range m.tunnels {
		if e.engine != nil {
			engines = append(engines, e.engine)
		}
	}
	m.mu.Unlock()

	if len(engines) == 0 {
		return nil
	}
	var all []string
	for _, eng := range engines {
		all = append(all, eng.ResolvedEndpointIPs()...)
	}
	return all
}

// ResolvedEndpoints returns the union of pre-resolved endpoint ip:port pairs
// from all active engines. Returns nil if no tunnel is connected.
func (m *Manager) ResolvedEndpoints() []string {
	m.mu.Lock()
	var engines []*Engine
	for _, e := range m.tunnels {
		if e.engine != nil {
			engines = append(engines, e.engine)
		}
	}
	m.mu.Unlock()

	if len(engines) == 0 {
		return nil
	}
	var all []string
	for _, eng := range engines {
		all = append(all, eng.ResolvedEndpoints()...)
	}
	return all
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
	for name, e := range m.tunnels {
		if e.state == domain.StateConnected || e.state == domain.StateConnecting || e.state == stateDisconnecting {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// AllDNSServers returns the union of DNS servers from all connected tunnels'
// configs. Used to re-apply the combined DNS when a tunnel connects or
// disconnects, preventing one tunnel from overwriting another's DNS settings.
func (m *Manager) AllDNSServers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := make(map[string]struct{})
	var all []string
	for _, e := range m.tunnels {
		if e.state == domain.StateConnected && e.cfg != nil {
			for _, dns := range e.cfg.Interface.DNS {
				if _, ok := seen[dns]; !ok {
					seen[dns] = struct{}{}
					all = append(all, dns)
				}
			}
		}
	}
	return all
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
