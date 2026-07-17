// Package reconnect handles automatic reconnection and dead connection detection.
package reconnect

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/steiale/wireguide/internal/tunnel"
)

// TunnelManager is the subset of tunnel.Manager that the reconnect monitor
// needs. Defined here (consumer-side interface) so tests can supply a mock
// without importing tunnel internals or spinning up real WireGuard state.
type TunnelManager interface {
	IsConnected() bool
	ActiveTunnel() string
	Status() *tunnel.ConnectionStatus
	AllStatuses() []*tunnel.ConnectionStatus
	Disconnect() error
	DisconnectTunnel(name string) error
}

// Config holds reconnection parameters.
type Config struct {
	HandshakeTimeout time.Duration // Max time without handshake before reconnecting (default: 120s)
	InitialDelay     time.Duration // First retry delay (default: 5s)
	MaxDelay         time.Duration // Max retry delay (default: 60s)
	MaxAttempts      int           // Max reconnection attempts (default: 0 = unlimited)
}

// DefaultConfig returns sensible default reconnection settings.
func DefaultConfig() Config {
	return Config{
		HandshakeTimeout: 120 * time.Second,
		InitialDelay:     5 * time.Second,
		MaxDelay:         60 * time.Second,
		MaxAttempts:      0, // unlimited — health check ensures persistent reconnection
	}
}

// State represents the current reconnection state.
type State struct {
	Reconnecting bool   `json:"reconnecting"`
	Attempt      int    `json:"attempt"`
	MaxAttempts  int    `json:"max_attempts"`
	NextRetry    string `json:"next_retry"`
}

// ReconnectFunc is called to perform the actual reconnection of a specific
// tunnel identified by name.
type ReconnectFunc func(name string) error

// StatusChangedFunc is called when reconnection state changes.
type StatusChangedFunc func(state State)

// FirewallSuspendFunc is called before disconnect during reconnection to
// temporarily disable firewall rules (kill switch / DNS protection). This
// prevents a deadlock when the utun interface name changes (e.g. utun4->utun5)
// and old pf rules block the new interface's traffic.
type FirewallSuspendFunc func() error

// FirewallResumeFunc is called after a successful reconnect to re-enable
// firewall rules with the new interface name and endpoints.
type FirewallResumeFunc func() error

// retryState is one tunnel's independent reconnectWithBackoff lifecycle:
// its cancel func, its exit signal, and its own attempt counter. Kept
// per-tunnel (in Monitor.retries, keyed by tunnel name) rather than as
// single shared Monitor fields — see that field's comment for why sharing
// them across tunnels was a real bug.
type retryState struct {
	cancel  context.CancelFunc
	done    chan struct{} // closed when reconnectWithBackoff exits
	attempt int
}

// Monitor watches tunnel health and triggers reconnection.
type Monitor struct {
	mu            sync.Mutex
	cfg           Config
	manager       TunnelManager
	reconnectFn   ReconnectFunc
	statusFn      StatusChangedFunc
	fwSuspendFn   FirewallSuspendFunc
	fwResumeFn    FirewallResumeFunc
	stopCh        chan struct{}
	wg            sync.WaitGroup
	running       bool
	sleepDetector SleepDetector

	// retries holds one independent retryState per tunnel name currently
	// being retried (the legacy "reconnect everything" path — used by
	// sleep/wake and manual Disconnect with no tunnel name — uses "" as its
	// key). This used to be a single set of shared fields
	// (retryCancel/retryDone/attempt), which meant triggering a reconnect
	// for tunnel B would cancel tunnel A's still-in-progress retry
	// goroutine outright (e.g. on wake with two active tunnels, or two
	// tunnels going handshake-stale around the same time) — A could be left
	// permanently disconnected, or worse, A's retry goroutine's own
	// success/give-up path could end up cancelling B's NEWER retry via the
	// shared retryCancel field once B's trigger had overwritten it. Keying
	// per-tunnel isolates each tunnel's backoff/cancel lifecycle completely.
	retries map[string]*retryState

	// healthCheckEnabled controls whether the periodic handshake age
	// check runs in monitorLoop. Can be toggled at runtime via
	// SetHealthCheck. Default: true.
	healthCheckEnabled bool

	// shouldReconnectFn is a per-tunnel callback that gates auto-reconnect
	// on wake / network change / stale handshake. If nil, no tunnel is
	// auto-reconnected (opt-in behaviour).
	shouldReconnectFn func(name string) bool
}

// NewMonitor creates a reconnection monitor.
func NewMonitor(manager TunnelManager, reconnectFn ReconnectFunc, statusFn StatusChangedFunc, cfg Config) *Monitor {
	return &Monitor{
		cfg:                cfg,
		manager:            manager,
		reconnectFn:        reconnectFn,
		statusFn:           statusFn,
		stopCh:             make(chan struct{}),
		sleepDetector:      NewSleepDetector(),
		healthCheckEnabled: false, // default OFF — enable in Settings
	}
}

// SetFirewallCallbacks configures the firewall suspend/resume callbacks used
// during reconnection. Must be called before Start(). Separated from
// NewMonitor to avoid changing the constructor signature for all callers.
func (m *Monitor) SetFirewallCallbacks(suspend FirewallSuspendFunc, resume FirewallResumeFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fwSuspendFn = suspend
	m.fwResumeFn = resume
}

// SetShouldReconnect sets a per-tunnel callback that controls whether a tunnel
// should be auto-reconnected on wake/network change. If nil, no tunnel is
// automatically reconnected (opt-in behaviour).
func (m *Monitor) SetShouldReconnect(fn func(name string) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldReconnectFn = fn
}

// SetHealthCheck enables or disables the periodic handshake age check.
// Safe to call while the monitor is running.
func (m *Monitor) SetHealthCheck(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthCheckEnabled = enabled
	slog.Info("health check toggled", "enabled", enabled)
}

// Start begins monitoring the tunnel connection.
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	// Recreate stopCh so Start() works after a previous Stop().
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("monitorLoop panic (recovered)",
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()))
			}
		}()
		m.monitorLoop()
	}()
	go func() {
		defer m.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("sleepWakeLoop panic (recovered)",
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()))
			}
		}()
		m.sleepWakeLoop()
	}()
	slog.Info("reconnect monitor started")
}

// Stop stops the monitor and waits for all goroutines to exit.
func (m *Monitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopCh)
	for name, rs := range m.retries {
		rs.cancel()
		delete(m.retries, name)
	}
	if m.sleepDetector != nil {
		m.sleepDetector.Stop()
	}
	m.mu.Unlock()

	// Wait for goroutines to exit outside the lock to avoid deadlock.
	// Use a timeout so a stuck goroutine doesn't block helper cleanup forever.
	waitDone := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		slog.Info("reconnect monitor stopped")
	case <-time.After(5 * time.Second):
		slog.Warn("reconnect monitor stop timed out after 5s, proceeding with cleanup")
	}
}

// CancelRetry aborts an in-flight reconnection attempt. Called by the helper
// when the user manually disconnects — we don't want a backoff sleep to wake
// up seconds later and re-connect against the user's wishes.
//
// tunnelName scopes the cancellation to that tunnel's own retry sequence
// only — disconnecting tunnel X must not abort tunnel Y's still-in-progress
// recovery, which is exactly what happened when this cancelled a single
// Monitor-wide retry regardless of which tunnel the caller actually meant.
// Pass "" for the legacy "disconnect everything" path, which cancels every
// active retry sequence (matching what a nameless Disconnect actually tears
// down helper-side).
func (m *Monitor) CancelRetry(tunnelName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tunnelName == "" {
		for name, rs := range m.retries {
			rs.cancel()
			delete(m.retries, name)
		}
		return
	}
	if rs, ok := m.retries[tunnelName]; ok {
		rs.cancel()
		delete(m.retries, tunnelName)
	}
}

// GetState returns an aggregate reconnection state across every tunnel
// currently being retried. Reconnecting is true if ANY tunnel has an active
// retry sequence; Attempt is the highest attempt count among them. This
// only approximates per-tunnel detail — real per-tunnel state is what
// notifyStatus/reconnectWithBackoff report at call time — but it's
// sufficient for the aggregate "is anything reconnecting" queries that use
// this method today.
func (m *Monitor) GetState() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	maxAttempt := 0
	for _, rs := range m.retries {
		if rs.attempt > maxAttempt {
			maxAttempt = rs.attempt
		}
	}
	return State{
		Reconnecting: len(m.retries) > 0,
		Attempt:      maxAttempt,
		MaxAttempts:  m.cfg.MaxAttempts,
	}
}

func (m *Monitor) monitorLoop() {
	const checkInterval = 30 * time.Second
	const handshakeStaleThreshold = 180 * time.Second // 3 minutes

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.mu.Lock()
			enabled := m.healthCheckEnabled
			m.mu.Unlock()
			if !enabled {
				continue
			}
			if !m.manager.IsConnected() {
				continue
			}
			// Check EACH tunnel's handshake individually. If a specific
			// tunnel is stale, disconnect and reconnect only THAT tunnel.
			statuses := m.manager.AllStatuses()
			for _, status := range statuses {
				if status == nil || status.LastHandshakeTime.IsZero() {
					continue
				}
				if status.State != "connected" {
					continue
				}
				age := time.Since(status.LastHandshakeTime)
				if age > handshakeStaleThreshold {
					tunnelName := status.TunnelName
					m.mu.Lock()
					shouldFn := m.shouldReconnectFn
					m.mu.Unlock()
					if shouldFn != nil && !shouldFn(tunnelName) {
						slog.Debug("skipping stale handshake reconnect (auto-reconnect disabled)", "tunnel", tunnelName)
						continue
					}
					slog.Warn("handshake stale, triggering per-tunnel reconnect",
						"tunnel", tunnelName,
						"last_handshake_age", age.Round(time.Second),
						"threshold", handshakeStaleThreshold)
					m.triggerReconnectTunnel(tunnelName)
				}
			}
		}
	}
}

func (m *Monitor) triggerReconnect() {
	// Reconnect all tunnels — used by sleep/wake detection.
	m.triggerReconnectTunnel("")
}

func (m *Monitor) triggerReconnectTunnel(tunnelName string) {
	m.mu.Lock()
	if m.retries == nil {
		m.retries = make(map[string]*retryState)
	}
	// Save the OLD entry for THIS tunnel name so we can clean it up outside
	// the lock — other tunnels' entries in the map are untouched.
	old := m.retries[tunnelName]

	// Create the new retry state and register it under the lock — no gap
	// for another goroutine to sneak in and create a duplicate
	// reconnectWithBackoff for the same tunnel.
	ctx, cancel := context.WithCancel(context.Background())
	rs := &retryState{cancel: cancel, done: make(chan struct{})}
	m.retries[tunnelName] = rs
	m.mu.Unlock()

	// Cancel the OLD retry goroutine for this SAME tunnel name outside the
	// lock to avoid deadlock. This never touches any other tunnel's entry.
	if old != nil {
		old.cancel()
		select {
		case <-old.done:
		case <-time.After(5 * time.Second):
			slog.Warn("timed out waiting for previous retry goroutine to exit", "tunnel", tunnelName)
		}
	}

	go func() {
		defer close(rs.done)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("reconnectWithBackoff panic (recovered)",
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()))
			}
		}()
		m.reconnectWithBackoff(ctx, tunnelName, rs)
	}()
}

// clearRetryState removes tunnelName's entry from m.retries, but ONLY if it
// still points at rs — i.e. only if no NEWER triggerReconnectTunnel call for
// the same tunnel has already replaced it. Without this guard, a
// slow-to-finish goroutine (e.g. one that just gave up after max attempts)
// could delete a different, newer retryState for the same tunnel name that
// superseded it in the interim.
func (m *Monitor) clearRetryState(tunnelName string, rs *retryState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.retries[tunnelName] == rs {
		delete(m.retries, tunnelName)
	}
}

// reconnectWithBackoff retries reconnection with exponential backoff.
// If tunnelName is non-empty, only that specific tunnel is disconnected and
// reconnected. If tunnelName is empty, the legacy Disconnect()/reconnectFn("")
// path is used (reconnects all tunnels, used by sleep/wake).
func (m *Monitor) reconnectWithBackoff(ctx context.Context, tunnelName string, rs *retryState) {
	delay := m.cfg.InitialDelay

	for {
		m.mu.Lock()
		if !m.running {
			m.mu.Unlock()
			return
		}
		rs.attempt++
		attempt := rs.attempt
		m.mu.Unlock()

		if m.cfg.MaxAttempts > 0 && attempt > m.cfg.MaxAttempts {
			slog.Error("max reconnection attempts reached", "attempts", m.cfg.MaxAttempts, "tunnel", tunnelName)
			m.notifyStatus(State{
				Reconnecting: false,
				Attempt:      attempt - 1,
				MaxAttempts:  m.cfg.MaxAttempts,
			})
			m.clearRetryState(tunnelName, rs)
			return
		}

		slog.Info("reconnecting", "attempt", attempt, "delay", delay, "tunnel", tunnelName)
		m.notifyStatus(State{
			Reconnecting: true,
			Attempt:      attempt,
			MaxAttempts:  m.cfg.MaxAttempts,
			NextRetry:    delay.String(),
		})

		// Cancelable backoff — responds immediately to CancelRetry()/Stop()
		// instead of waiting out the full delay.
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			slog.Info("reconnection cancelled", "attempt", attempt)
			return
		case <-m.stopCh:
			timer.Stop()
			return
		case <-timer.C:
		}

		// Recheck cancellation after the sleep returned normally — the user
		// may have clicked Disconnect between the timer firing and this line.
		// Without this check a final reconnectFn() would run against the
		// user's explicit wish and silently bring the tunnel back up.
		if ctx.Err() != nil {
			slog.Info("reconnection cancelled before attempt", "attempt", attempt)
			return
		}

		// Suspend firewall rules before disconnect so old pf rules (which
		// reference the old utun interface name) don't block the new
		// connection's traffic when the interface name changes.
		firewallWasSuspended := false
		if m.fwSuspendFn != nil {
			if err := m.fwSuspendFn(); err != nil {
				slog.Warn("failed to suspend firewall for reconnect", "error", err)
			} else {
				firewallWasSuspended = true
			}
		}

		// Disconnect the specific tunnel (or first tunnel for legacy path).
		if tunnelName != "" {
			_ = m.manager.DisconnectTunnel(tunnelName)
		} else {
			_ = m.manager.Disconnect()
		}

		// One more cancellation check before the actual reconnect — manager
		// Disconnect can take a moment and the user's cancel may land here.
		if ctx.Err() != nil {
			slog.Info("reconnection cancelled before reconnectFn", "attempt", attempt)
			// Re-enable firewall even on cancel to avoid leaving the
			// system unprotected.
			if firewallWasSuspended && m.fwResumeFn != nil {
				if err := m.fwResumeFn(); err != nil {
					slog.Warn("failed to resume firewall after cancel", "error", err)
				}
			}
			return
		}

		// Attempt reconnection — pass tunnel name so only the specific
		// tunnel is reconnected when doing per-tunnel health recovery.
		if err := m.reconnectFn(tunnelName); err != nil {
			slog.Warn("reconnection failed", "attempt", attempt, "tunnel", tunnelName, "error", err)
			// Re-enable firewall after failed attempt so the system stays
			// protected between retries.
			if firewallWasSuspended && m.fwResumeFn != nil {
				if err := m.fwResumeFn(); err != nil {
					slog.Warn("failed to resume firewall after failed reconnect", "error", err)
				}
			}
			// Exponential backoff
			delay *= 2
			if delay > m.cfg.MaxDelay {
				delay = m.cfg.MaxDelay
			}
			continue
		}

		// Resume firewall with the new interface name and endpoints.
		if firewallWasSuspended && m.fwResumeFn != nil {
			if err := m.fwResumeFn(); err != nil {
				slog.Warn("failed to resume firewall after successful reconnect", "error", err)
			}
		}

		slog.Info("reconnected successfully", "attempt", attempt, "tunnel", tunnelName)
		m.notifyStatus(State{Reconnecting: false})
		m.clearRetryState(tunnelName, rs)
		return
	}
}

func (m *Monitor) sleepWakeLoop() {
	if m.sleepDetector == nil {
		return
	}
	m.sleepDetector.Start()

	wakeCh := m.sleepDetector.WakeChan()
	for {
		select {
		case <-m.stopCh:
			return
		case <-wakeCh:
			slog.Info("system wake detected, checking per-tunnel auto-reconnect")
			m.mu.Lock()
			shouldFn := m.shouldReconnectFn
			m.mu.Unlock()
			statuses := m.manager.AllStatuses()
			for _, status := range statuses {
				if status == nil {
					continue
				}
				name := status.TunnelName
				if shouldFn != nil && shouldFn(name) {
					slog.Info("auto-reconnecting tunnel on wake", "tunnel", name)
					m.triggerReconnectTunnel(name)
				}
			}
		}
	}
}

func (m *Monitor) notifyStatus(state State) {
	if m.statusFn != nil {
		m.statusFn(state)
	}
}
