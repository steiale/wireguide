// Package reconnect handles automatic reconnection and dead connection detection.
package reconnect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/tunnel"
)

// TunnelManager is the subset of tunnel.Manager the monitor needs.
type TunnelManager interface {
	IsConnected() bool
	AllStatuses() []*tunnel.ConnectionStatus
	DisconnectTunnel(name string) error
}

// Config holds reconnection parameters.
type Config struct {
	InitialDelay time.Duration // First retry delay (default: 5s)
	MaxDelay     time.Duration // Max retry delay (default: 60s)
	MaxAttempts  int           // Max reconnection attempts (0 = unlimited)
	// WakeGrace is how long after a wake a WireGuard tunnel gets to complete
	// a fresh handshake on its own before it is reconnected.
	WakeGrace time.Duration
}

// DefaultConfig returns sensible default reconnection settings.
func DefaultConfig() Config {
	return Config{
		InitialDelay: 5 * time.Second,
		MaxDelay:     60 * time.Second,
		MaxAttempts:  0,
		WakeGrace:    30 * time.Second,
	}
}

// State represents the current reconnection state.
type State struct {
	Reconnecting bool   `json:"reconnecting"`
	Attempt      int    `json:"attempt"`
	MaxAttempts  int    `json:"max_attempts"`
	NextRetry    string `json:"next_retry"`
}

// ErrGiveUp, returned (possibly wrapped) by a ReconnectFunc, ends the retry
// sequence instead of backing off — e.g. the user disconnected the tunnel.
var ErrGiveUp = errors.New("reconnect abandoned")

// ReconnectFunc reconnects the named tunnel.
type ReconnectFunc func(name string) error

// StatusChangedFunc is called when reconnection state changes.
type StatusChangedFunc func(state State)

// FirewallHoldFunc is called with a tunnel name when its retry sequence
// starts (suspend) and when it ends for any reason (resume). Between the two
// the firewall keeps passing the tunnel's server endpoint so the reconnect
// can get through a kill switch.
type FirewallHoldFunc func(tunnelName string) error

// retryState is one tunnel's reconnectWithBackoff lifecycle.
type retryState struct {
	cancel  context.CancelFunc
	done    chan struct{} // closed when reconnectWithBackoff exits
	attempt int
}

// Monitor watches tunnel health and triggers reconnection.
type Monitor struct {
	mu          sync.Mutex
	cfg         Config
	manager     TunnelManager
	reconnectFn ReconnectFunc
	statusFn    StatusChangedFunc
	fwSuspendFn FirewallHoldFunc
	fwResumeFn  FirewallHoldFunc
	stopCh      chan struct{}
	// wg is replaced on every Start() so a Stop() still waiting on the
	// previous run's goroutines never shares a WaitGroup with a new run.
	wg            *sync.WaitGroup
	running       bool
	sleepDetector SleepDetector

	// retries holds an independent retry sequence per tunnel name, so one
	// tunnel's retry never cancels another's.
	retries map[string]*retryState

	healthCheckEnabled bool

	// shouldReconnectFn gates auto-reconnect per tunnel. nil = never.
	shouldReconnectFn func(name string) bool
}

// NewMonitor creates a reconnection monitor.
func NewMonitor(manager TunnelManager, reconnectFn ReconnectFunc, statusFn StatusChangedFunc, cfg Config) *Monitor {
	return &Monitor{
		cfg:           cfg,
		manager:       manager,
		reconnectFn:   reconnectFn,
		statusFn:      statusFn,
		stopCh:        make(chan struct{}),
		wg:            &sync.WaitGroup{},
		sleepDetector: NewSleepDetector(),
	}
}

// SetFirewallCallbacks configures the firewall hold callbacks. Must be
// called before Start().
func (m *Monitor) SetFirewallCallbacks(suspend, resume FirewallHoldFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fwSuspendFn = suspend
	m.fwResumeFn = resume
}

// SetShouldReconnect sets the per-tunnel auto-reconnect gate.
func (m *Monitor) SetShouldReconnect(fn func(name string) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldReconnectFn = fn
}

// SetHealthCheck enables or disables the periodic handshake age check.
func (m *Monitor) SetHealthCheck(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthCheckEnabled = enabled
	slog.Info("health check toggled", "enabled", enabled)
}

// Start begins monitoring.
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.stopCh = make(chan struct{})
	wg := &sync.WaitGroup{}
	m.wg = wg
	wg.Add(2)
	m.mu.Unlock()

	go m.guard(wg, "monitorLoop", m.monitorLoop)
	go m.guard(wg, "sleepWakeLoop", m.sleepWakeLoop)
	slog.Info("reconnect monitor started")
}

func (m *Monitor) guard(wg *sync.WaitGroup, name string, fn func()) {
	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error(name+" panic (recovered)", "panic", fmt.Sprintf("%v", r), "stack", string(debug.Stack()))
		}
	}()
	fn()
}

// Stop stops the monitor and waits (up to 5s) for its goroutines to exit.
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
	wg := m.wg
	m.mu.Unlock()

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		slog.Info("reconnect monitor stopped")
	case <-time.After(5 * time.Second):
		slog.Warn("reconnect monitor stop timed out after 5s, proceeding with cleanup")
	}
}

// CancelRetry aborts tunnelName's in-flight retry sequence, if any (the
// user disconnected it).
func (m *Monitor) CancelRetry(tunnelName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rs, ok := m.retries[tunnelName]; ok {
		rs.cancel()
		delete(m.retries, tunnelName)
	}
}

func (m *Monitor) shouldReconnect(name string) bool {
	m.mu.Lock()
	fn := m.shouldReconnectFn
	m.mu.Unlock()
	return fn != nil && fn(name)
}

func (m *Monitor) monitorLoop() {
	const checkInterval = 30 * time.Second
	const handshakeStaleThreshold = 180 * time.Second

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
			if !enabled || !m.manager.IsConnected() {
				continue
			}
			for _, status := range m.manager.AllStatuses() {
				if status == nil || status.State != domain.StateConnected || status.LastHandshakeTime.IsZero() {
					continue
				}
				age := time.Since(status.LastHandshakeTime)
				if age <= handshakeStaleThreshold || !m.shouldReconnect(status.TunnelName) {
					continue
				}
				slog.Warn("handshake stale, triggering per-tunnel reconnect",
					"tunnel", status.TunnelName,
					"last_handshake_age", age.Round(time.Second),
					"threshold", handshakeStaleThreshold)
				m.triggerReconnectTunnel(status.TunnelName)
			}
		}
	}
}

func (m *Monitor) triggerReconnectTunnel(tunnelName string) {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	if m.retries == nil {
		m.retries = make(map[string]*retryState)
	}
	old := m.retries[tunnelName]
	ctx, cancel := context.WithCancel(context.Background())
	rs := &retryState{cancel: cancel, done: make(chan struct{})}
	m.retries[tunnelName] = rs
	wg := m.wg
	wg.Add(1)
	suspend := m.fwSuspendFn
	m.mu.Unlock()

	// The new sequence's firewall hold is taken BEFORE the old sequence is
	// cancelled: holds are counted, so the old sequence's release then only
	// drops its own count and never ends the hold (which, with the tunnel
	// down, would briefly block it as a give-up). reconnectWithBackoff
	// releases this hold on every exit path.
	if suspend != nil {
		if err := suspend(tunnelName); err != nil {
			slog.Warn("failed to hold firewall for reconnect", "tunnel", tunnelName, "error", err)
		}
	}

	// Replace an older sequence for the same tunnel (outside the lock).
	if old != nil {
		old.cancel()
		select {
		case <-old.done:
		case <-time.After(5 * time.Second):
			slog.Warn("timed out waiting for previous retry goroutine to exit", "tunnel", tunnelName)
		}
	}

	// Tracked in m.wg so Stop() waits for the firewall resume on the way out.
	go func() {
		defer wg.Done()
		defer close(rs.done)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("reconnectWithBackoff panic (recovered)",
					"panic", fmt.Sprintf("%v", r), "stack", string(debug.Stack()))
			}
		}()
		m.reconnectWithBackoff(ctx, tunnelName, rs)
	}()
}

// clearRetryState removes tunnelName's entry only if it is still rs (a newer
// sequence may have replaced it).
func (m *Monitor) clearRetryState(tunnelName string, rs *retryState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.retries[tunnelName] == rs {
		delete(m.retries, tunnelName)
	}
}

// reconnectWithBackoff retries one tunnel with exponential backoff. The
// firewall hold (taken by triggerReconnectTunnel) spans the WHOLE sequence,
// backoff waits included: releasing it between attempts would drop the kill
// switch while the tunnel is down. It is released here on exit.
func (m *Monitor) reconnectWithBackoff(ctx context.Context, tunnelName string, rs *retryState) {
	m.mu.Lock()
	resume := m.fwResumeFn
	m.mu.Unlock()
	if resume != nil {
		defer func() {
			if err := resume(tunnelName); err != nil {
				slog.Warn("failed to release firewall hold after reconnect", "tunnel", tunnelName, "error", err)
			}
		}()
	}
	defer m.clearRetryState(tunnelName, rs)

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
			m.notifyStatus(State{Attempt: attempt - 1, MaxAttempts: m.cfg.MaxAttempts})
			return
		}

		slog.Info("reconnecting", "attempt", attempt, "delay", delay, "tunnel", tunnelName)
		m.notifyStatus(State{
			Reconnecting: true,
			Attempt:      attempt,
			MaxAttempts:  m.cfg.MaxAttempts,
			NextRetry:    delay.String(),
		})

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			slog.Info("reconnection cancelled", "attempt", attempt, "tunnel", tunnelName)
			return
		case <-m.stopCh:
			timer.Stop()
			return
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return
		}

		_ = m.manager.DisconnectTunnel(tunnelName) // stale tunnel, if still up
		if ctx.Err() != nil {
			return
		}

		err := m.reconnectFn(tunnelName)
		if err == nil {
			slog.Info("reconnected successfully", "attempt", attempt, "tunnel", tunnelName)
			m.notifyStatus(State{Reconnecting: false})
			return
		}
		if errors.Is(err, ErrGiveUp) {
			slog.Info("reconnection abandoned", "tunnel", tunnelName, "reason", err)
			m.notifyStatus(State{Reconnecting: false})
			return
		}
		slog.Warn("reconnection failed", "attempt", attempt, "tunnel", tunnelName, "error", err)
		delay = min(delay*2, m.cfg.MaxDelay)
	}
}

// sleepWakeLoop reconnects tunnels that did not recover by themselves after
// a wake. WireGuard normally re-handshakes on its own (and the route monitor
// re-points bypass routes), so healthy tunnels are not torn down: only those
// without a handshake since the wake, once WakeGrace has passed.
func (m *Monitor) sleepWakeLoop() {
	if m.sleepDetector == nil {
		return
	}
	m.sleepDetector.Start()
	wakeCh := m.sleepDetector.WakeChan()

	var grace *time.Timer
	var graceC <-chan time.Time
	var wokeAt time.Time
	defer func() {
		if grace != nil {
			grace.Stop()
		}
	}()
	for {
		select {
		case <-m.stopCh:
			return
		case <-wakeCh:
			slog.Info("system wake detected, checking tunnels after grace period", "grace", m.cfg.WakeGrace)
			wokeAt = time.Now().Round(0) // wall clock: handshake times are wall clock
			if grace != nil {
				grace.Stop()
			}
			grace = time.NewTimer(m.cfg.WakeGrace)
			graceC = grace.C
		case <-graceC:
			graceC = nil
			for _, status := range m.manager.AllStatuses() {
				if status == nil || !m.shouldReconnect(status.TunnelName) {
					continue
				}
				if status.State == domain.StateConnected && status.LastHandshakeTime.After(wokeAt) {
					continue
				}
				slog.Info("tunnel has no handshake since wake, reconnecting", "tunnel", status.TunnelName)
				m.triggerReconnectTunnel(status.TunnelName)
			}
		}
	}
}

// NotifyTunnelDied triggers a reconnect for a tunnel that died on its own
// (engine or openvpn process death), if auto-reconnect is enabled for it.
func (m *Monitor) NotifyTunnelDied(tunnelName string) {
	if !m.shouldReconnect(tunnelName) {
		slog.Warn("tunnel died, auto-reconnect disabled for this tunnel — leaving disconnected", "tunnel", tunnelName)
		return
	}
	slog.Warn("tunnel died unexpectedly, triggering reconnect", "tunnel", tunnelName)
	m.triggerReconnectTunnel(tunnelName)
}

func (m *Monitor) notifyStatus(state State) {
	if m.statusFn != nil {
		m.statusFn(state)
	}
}
