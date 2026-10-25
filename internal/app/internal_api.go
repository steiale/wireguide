package app

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/storage"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// This file is the Go-only surface of TunnelService. Wails binds EVERY
// exported method on a registered service, so anything that only internal/gui
// needs (wiring, history bookkeeping, path grants) lives here as package-level
// functions over unexported methods — keeping it off the JavaScript-callable
// surface of the webview.

// SetApp injects the Wails app (dialogs, browser, autostart).
func SetApp(s *TunnelService, app *application.App) { s.setApp(app) }

// SetWindow injects the main window so ResizeToFit can adjust its height.
func SetWindow(s *TunnelService, win *application.WebviewWindow) { s.setWindow(win) }

// ListTunnelsLocal returns stored tunnels without an IPC round-trip (tray).
func ListTunnelsLocal(s *TunnelService) ([]TunnelInfo, error) { return s.listTunnelsLocal() }

// ActiveTunnelNames returns every tunnel the helper tracks: running, or
// protected (reconnecting, or blocked by the kill switch). Disconnecting
// each releases all of them.
func ActiveTunnelNames(s *TunnelService) ([]string, error) { return s.trackedTunnelNames() }

// ReconcileHistoryFromStatus syncs history sessions against helper status.
func ReconcileHistoryFromStatus(s *TunnelService, activeNames []string, rxByTunnel, txByTunnel map[string]int64, disappearReason string) {
	s.reconcileHistoryFromStatus(activeNames, rxByTunnel, txByTunnel, disappearReason)
}

// CloseHistorySessions closes every open history session with reason.
func CloseHistorySessions(s *TunnelService, reason string) { s.closeHistorySessions(reason) }

// MigrateAutostart moves legacy LaunchAgent users to the SMAppService item.
func MigrateAutostart(s *TunnelService) { s.migrateAutostart() }

// GrantPaths authorizes the path-taking bindings (ReadFile, ImportZip,
// ImportQRFromPath, ImportFoundConfigs) to open exactly these paths, once
// each, within pathGrantTTL. Called by internal/gui for native file drops.
func GrantPaths(s *TunnelService, paths []string) { s.grantPaths(paths) }

// PushFirewallPolicy sends the persisted kill-switch and DNS-protection
// policy to the helper behind c. Called by internal/gui after every helper
// (re)connect, since a restarted helper starts with its defaults.
func PushFirewallPolicy(c *ipc.Client, st *storage.Settings) error {
	if c == nil || st == nil {
		return nil
	}
	ksErr := c.Call(ipc.MethodSetKillSwitch, ipc.KillSwitchRequest{Enabled: st.KillSwitch}, nil)
	dnsErr := c.Call(ipc.MethodSetDNSProtection, ipc.DNSProtectionRequest{Enabled: st.DNSProtection}, nil)
	return errors.Join(ksErr, dnsErr)
}

// pathGrantTTL bounds how long a path handed to the frontend stays usable.
// Long enough for the onboarding scan list to sit on screen while the user
// picks configs; short enough that a stale grant is not a standing capability.
const pathGrantTTL = 5 * time.Minute

// grantPaths records paths the Go side itself handed to the frontend (drop
// events, scan results). The frontend can only pass these back — a
// compromised webview cannot name arbitrary files for us to read.
func (s *TunnelService) grantPaths(paths []string) {
	now := time.Now()
	s.pathGrantsMu.Lock()
	defer s.pathGrantsMu.Unlock()
	if s.pathGrants == nil {
		s.pathGrants = make(map[string]time.Time)
	}
	for p, exp := range s.pathGrants {
		if now.After(exp) {
			delete(s.pathGrants, p)
		}
	}
	for _, p := range paths {
		if p == "" || !filepath.IsAbs(p) {
			continue
		}
		s.pathGrants[filepath.Clean(p)] = now.Add(pathGrantTTL)
	}
}

// consumePath checks and removes a single-use grant for path.
func (s *TunnelService) consumePath(path string) error {
	key := filepath.Clean(path)
	s.pathGrantsMu.Lock()
	defer s.pathGrantsMu.Unlock()
	exp, ok := s.pathGrants[key]
	if ok {
		delete(s.pathGrants, key)
	}
	if !ok || time.Now().After(exp) {
		return fmt.Errorf("path not authorized: %s (drop or rescan the file again)", path)
	}
	return nil
}
