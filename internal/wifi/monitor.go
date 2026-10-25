package wifi

import (
	"log/slog"
	"sync"
	"time"
)

// SSIDChangedFunc is called when the WiFi SSID changes.
type SSIDChangedFunc func(oldSSID, newSSID string)

// Monitor watches for WiFi SSID changes and triggers actions.
type Monitor struct {
	mu        sync.Mutex
	rules     *Rules
	onChanged SSIDChangedFunc
	lastSSID  string
	stopCh    chan struct{}
	recheck   chan struct{} // buffered(1): coalesced "poll now" requests
	running   bool
	readSSID  func() string // CurrentSSID; swapped in tests
}

// NewMonitor creates a WiFi monitor.
func NewMonitor(rules *Rules, onChanged SSIDChangedFunc) *Monitor {
	return &Monitor{
		rules:     rules,
		onChanged: onChanged,
		recheck:   make(chan struct{}, 1),
		readSSID:  CurrentSSID,
	}
}

// Recheck asks the running poller to read the SSID immediately instead of
// waiting for the next tick — used when Location authorization changes, so
// rules start firing the moment the user grants access. Non-blocking.
func (m *Monitor) Recheck() {
	select {
	case m.recheck <- struct{}{}:
	default:
	}
}

// Start begins monitoring WiFi SSID changes. Safe to call multiple times;
// subsequent calls are no-ops while the monitor is already running.
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	stop := make(chan struct{})
	m.stopCh = stop
	m.mu.Unlock()
	go m.poll(stop)
	slog.Info("WiFi monitor started")
}

// Stop stops the monitor.
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return
	}
	m.running = false
	close(m.stopCh)
}

// UpdateRules updates the auto-connect rules.
func (m *Monitor) UpdateRules(rules *Rules) {
	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()
}

// poll owns stop, so a Stop+Start can never leave the old poller reading
// the new channel.
func (m *Monitor) poll(stop <-chan struct{}) {
	initial := m.readSSID()
	m.mu.Lock()
	m.lastSSID = initial
	m.mu.Unlock()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			m.check()
		case <-m.recheck:
			m.check()
		}
	}
}

// check reads the SSID and fires onChanged when it differs from the last one.
func (m *Monitor) check() {
	current := m.readSSID()
	m.mu.Lock()
	if current == m.lastSSID {
		m.mu.Unlock()
		return
	}
	slog.Info("WiFi SSID changed", "from", m.lastSSID, "to", current)
	old := m.lastSSID
	m.lastSSID = current
	m.mu.Unlock()
	if m.onChanged != nil {
		m.onChanged(old, current)
	}
}
