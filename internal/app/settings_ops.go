package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"

	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/storage"
	"github.com/steiale/wireguide/internal/update"
)

// guiLogLevelSetter is set by internal/gui at startup so the app package
// (which is Wails-bound) can update the GUI process's own log level at
// runtime without importing internal/gui (which would create an import
// cycle). SetLogLevel below calls this in addition to forwarding the
// level to the helper. Uses atomic.Value for safe concurrent access.
var guiLogLevelSetter atomic.Value // stores func(string)

// SetGUILogLevelSetter is called once from internal/gui.Run to register
// the GUI-side log level mutator. Safe to call before NewTunnelService.
func SetGUILogLevelSetter(f func(string)) {
	guiLogLevelSetter.Store(f)
}

func getGUILogLevelSetter() func(string) {
	if v := guiLogLevelSetter.Load(); v != nil {
		return v.(func(string))
	}
	return nil
}

// --- Settings (all local, no IPC) ---

func (s *TunnelService) GetSettings() (*storage.Settings, error) {
	return s.settingsStore.Load()
}

// SaveSettings persists the settings file AND applies any side effects:
// currently, pushing the new log level to both the GUI's slog handler and
// the helper's slog handler. Without those side effects a user lowering the
// level to Debug wouldn't see any new records — the saved file would match
// the UI but the running process would still be at Info.
func (s *TunnelService) SaveSettings(settings *storage.Settings) error {
	// Read the previous state first so we only (un)register the login item
	// when the user actually toggles it.
	prev, _ := s.settingsStore.Load()

	// Register/unregister BEFORE persisting so a failed registration never
	// leaves AutoStart=true on disk while nothing actually launches at login.
	if prev == nil || prev.AutoStart != settings.AutoStart {
		if err := s.setAutostart(settings.AutoStart); err != nil {
			return err
		}
	}

	if err := s.settingsStore.Save(settings); err != nil {
		return err
	}

	if settings.LogLevel != "" {
		if fn := getGUILogLevelSetter(); fn != nil {
			fn(settings.LogLevel)
		}
		// Best-effort: the helper may be unreachable during shutdown, and
		// the level change is not critical to Save succeeding.
		_ = s.call(ipc.MethodSetLogLevel, ipc.SetLogLevelRequest{Level: settings.LogLevel}, nil)
	}
	return nil
}

// SetLogLevel updates both the GUI's and the helper's slog level
// immediately. Exposed as a Wails method so the Settings view can call
// it without waiting for a full SaveSettings round trip.
func (s *TunnelService) SetLogLevel(level string) error {
	if fn := getGUILogLevelSetter(); fn != nil {
		fn(level)
	}
	return s.call(ipc.MethodSetLogLevel, ipc.SetLogLevelRequest{Level: level}, nil)
}

// --- Firewall policy (go through helper) ---
//
// Kill switch and DNS protection are POLICIES held by the helper: it applies
// them to any active tunnel immediately and to every future connect
// (WireGuard and OpenVPN), and derives the DNS servers itself. The GUI's job
// is to keep the helper's policy equal to the persisted setting — these
// setters push the new value and persist it; bootstrapHelper / helper
// recovery push the persisted values on every (re)connect.

// SetKillSwitch sets the kill-switch policy and persists it.
func (s *TunnelService) SetKillSwitch(enabled bool) error {
	return s.setFirewallPolicy(ipc.MethodSetKillSwitch, ipc.KillSwitchRequest{Enabled: enabled},
		func(st *storage.Settings) { st.KillSwitch = enabled })
}

// SetDNSProtection sets the DNS-protection policy and persists it.
func (s *TunnelService) SetDNSProtection(enabled bool) error {
	return s.setFirewallPolicy(ipc.MethodSetDNSProtection, ipc.DNSProtectionRequest{Enabled: enabled},
		func(st *storage.Settings) { st.DNSProtection = enabled })
}

// setFirewallPolicy pushes a policy change to the helper, then persists it.
// With no helper connected yet the value is only persisted: the bootstrap /
// recovery path pushes persisted policy as soon as a helper is available.
// A helper-side rejection is returned without persisting.
func (s *TunnelService) setFirewallPolicy(method string, req any, apply func(*storage.Settings)) error {
	if err := s.call(method, req, nil); err != nil && !errors.Is(err, errHelperUnavailable) {
		return err
	}
	st, err := s.settingsStore.Load()
	if err != nil {
		return err
	}
	apply(st)
	return s.settingsStore.Save(st)
}

// expectedDNSFor returns the DNS servers a tunnel is expected to be using.
// WireGuard's DNS list is a static client-side directive, readable straight
// from the parsed .conf. OpenVPN DNS is pushed by the server at connect time,
// so status.DNSServers is the only source for it. Used by RunDNSLeakTest.
func (s *TunnelService) expectedDNSFor(tunnelName string) []string {
	if tunnelName == "" {
		return nil
	}
	if s.tunnelStore.IsOVPN(tunnelName) {
		if status, err := s.GetStatus(); err == nil && status != nil {
			return status.DNSServers
		}
		return nil
	}
	if cfg, err := s.tunnelStore.Load(tunnelName); err == nil && cfg != nil {
		return cfg.Interface.DNS
	}
	return nil
}

// --- Auto-update ---

// SetPinInterface enables or disables -ifscope bypass route pinning.
func (s *TunnelService) SetPinInterface(enabled bool) error {
	return s.call(ipc.MethodSetPinInterface, ipc.SetPinInterfaceRequest{Enabled: enabled}, nil)
}

// SetHealthCheck enables or disables the tunnel health check monitor.
func (s *TunnelService) SetHealthCheck(enabled bool) error {
	return s.call(ipc.MethodSetHealthCheck, ipc.SetHealthCheckRequest{Enabled: enabled}, nil)
}

// allowedOpenURLs is the exact-match list of URLs OpenURL will open. We
// hardcode the specific URLs the app actually links to (release notes, issue
// tracker, license, repo home) instead of allowing anything under
// https://github.com/, which would let a compromised frontend redirect users
// to attacker-controlled repos hosted on the same domain.
var allowedOpenURLs = map[string]struct{}{
	// Releases page — used by the auto-update fallback.
	"https://github.com/steiale/wireguide/releases/latest": {},
	// Repo home / issues / license — linked from the Settings "About" panel.
	// The frontend currently points at the steiale/wireguide org; both
	// owners' canonical pages are listed so the existing UI keeps working
	// without silently breaking.
	"https://github.com/steiale/wireguide":                   {},
	"https://github.com/steiale/wireguide/issues":            {},
	"https://github.com/steiale/wireguide/blob/main/LICENSE": {},
	// Ko-fi donation page — linked from Settings About and the one-time banner.
	"https://ko-fi.com/steiale": {},
}

// OpenURL opens a URL in the default browser. Only an explicit allowlist of
// known-safe URLs is accepted to prevent a compromised frontend from
// redirecting the user to an attacker-controlled GitHub page.
func (s *TunnelService) OpenURL(url string) error {
	if _, ok := allowedOpenURLs[url]; !ok {
		return fmt.Errorf("URL not allowed: %s", url)
	}
	if s.app != nil {
		return s.app.Browser.OpenURL(url)
	}
	return fmt.Errorf("app not initialized")
}

// GetVersion returns the current app version string.
func (s *TunnelService) GetVersion() string {
	return update.CurrentVersion()
}

// CheckForUpdate queries GitHub for a newer release. The result is cached in
// Go so RunUpdate acts on what Go fetched, never on frontend-supplied data.
func (s *TunnelService) CheckForUpdate() (*update.UpdateInfo, error) {
	info, err := update.CheckForUpdate()
	if err != nil {
		return nil, err
	}
	s.updateMu.Lock()
	if info != nil && info.Available {
		cached := *info
		s.lastUpdate = &cached
	} else {
		s.lastUpdate = nil
	}
	s.updateMu.Unlock()
	return info, nil
}

// cachedUpdate returns a copy of the last CheckForUpdate result if it offers
// exactly version.
func (s *TunnelService) cachedUpdate(version string) (*update.UpdateInfo, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if s.lastUpdate == nil || !s.lastUpdate.Available {
		return nil, fmt.Errorf("no update available — check for updates first")
	}
	if version == "" || s.lastUpdate.Version != version {
		return nil, fmt.Errorf("update %q does not match the last checked release %q", version, s.lastUpdate.Version)
	}
	info := *s.lastUpdate
	info.HashVerified = false
	info.SignatureVerified = false
	return &info, nil
}

// RunUpdate performs the update to version, which must match the release
// found by the last CheckForUpdate. If installed via Homebrew, runs brew
// upgrade (the cask relaunches the app) and returns "". Otherwise downloads
// and verifies the asset from GitHub Releases, reveals it in Finder, and
// returns its path so the UI can tell the user what to do next.
func (s *TunnelService) RunUpdate(version string) (string, error) {
	info, err := s.cachedUpdate(version)
	if err != nil {
		return "", err
	}

	if update.IsBrewInstall() {
		brewBin := update.BrewPath()
		// Update tap first to ensure latest cask version is fetched
		slog.Info("update: running brew update", "brew", brewBin)
		if out, err := exec.Command(brewBin, "update").CombinedOutput(); err != nil {
			slog.Warn("brew update failed, continuing with upgrade", "error", err, "output", string(out))
		}
		slog.Info("update: running brew upgrade --cask lockplus")
		cmd := exec.Command(brewBin, "upgrade", "--cask", "lockplus")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("brew upgrade failed: %w (%s)", err, string(out))
		}
		// postflight in the cask handles killall + relaunch
		return "", nil
	}

	// Non-brew installs: download the asset, verify its SHA-256, then reveal
	// the verified file in Finder so the user can drag-replace the app
	// bundle manually. Auto-replacing the running .app needs elevated
	// privileges and has many failure modes — same UX as most indie macOS
	// apps. If anything in the download/verify pipeline fails (no checksum,
	// network down, hash mismatch), we surface the error to the GUI; the
	// user can fall back to the Releases page from the dialog.
	slog.Info("update: downloading + verifying asset (non-brew install)")
	dlPath, err := update.DownloadUpdate(info)
	if err != nil {
		// If verification failed or download failed, fall back to opening
		// the releases page rather than blocking the user entirely. The
		// download error is logged so curious users can find it in the
		// log viewer.
		slog.Warn("update: download/verify failed, opening Releases page as fallback", "error", err)
		if s.app != nil {
			_ = s.app.Browser.OpenURL("https://github.com/steiale/wireguide/releases/latest")
		} else {
			_ = exec.Command("/usr/bin/open", "https://github.com/steiale/wireguide/releases/latest").Run()
		}
		return "", fmt.Errorf("download/verify failed: %w", err)
	}
	if err := update.Install(dlPath, info); err != nil {
		return "", fmt.Errorf("install (reveal): %w", err)
	}
	return dlPath, nil
}

// ScanForWireGuardConfigs returns existing WireGuard configs found on the
// filesystem that haven't been imported into LockPlus yet.
func (t *TunnelService) ScanForWireGuardConfigs() []FoundConfig {
	list, _ := t.tunnelStore.List()
	existing := make(map[string]bool, len(list))
	for _, n := range list {
		existing[n] = true
	}
	found := scanSystemWireGuardConfigs(existing)
	paths := make([]string, 0, len(found))
	for _, f := range found {
		paths = append(paths, f.Path)
	}
	t.grantPaths(paths)
	return found
}

// ImportFoundConfigs reads and imports the .conf files at the given absolute
// paths. Returns per-file results reusing the ZipImportResult shape. Only
// paths returned by ScanForWireGuardConfigs are accepted, once each.
func (t *TunnelService) ImportFoundConfigs(paths []string) []ZipImportResult {
	var results []ZipImportResult
	for _, p := range paths {
		name, ext := stripKnownTunnelExt(filepath.Base(p))
		if err := t.consumePath(p); err != nil {
			results = append(results, ZipImportResult{Name: name, Error: err.Error()})
			continue
		}
		if fi, err := os.Stat(p); err == nil && fi.Size() > maxReadFileSize {
			results = append(results, ZipImportResult{Name: name, Error: fmt.Sprintf("file too large (max %d bytes)", maxReadFileSize)})
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			results = append(results, ZipImportResult{Name: name, Error: err.Error()})
			continue
		}
		if info, err := t.importNamed(name, ext, string(data)); err != nil {
			results = append(results, ZipImportResult{Name: name, Error: err.Error()})
		} else {
			results = append(results, ZipImportResult{Name: info.Name})
		}
	}
	return results
}

// CompleteOnboarding marks onboarding as done in settings.
func (t *TunnelService) CompleteOnboarding() error {
	s, err := t.settingsStore.Load()
	if err != nil {
		return err
	}
	s.OnboardingComplete = true
	return t.settingsStore.Save(s)
}

// GetTunnelMeta returns per-tunnel metadata (auto-reconnect flag etc.).
func (t *TunnelService) GetTunnelMeta(name string) (*storage.TunnelMeta, error) {
	return t.tunnelStore.LoadMeta(name)
}

// SaveTunnelMeta persists per-tunnel metadata. The frontend only sends the
// fields it knows about (auto_reconnect, notes), so we read the existing meta
// first and preserve any fields the caller didn't set — in particular Protocol,
// which would otherwise be blanked out and cause an OpenVPN tunnel to be
// treated as WireGuard on the next load.
func (t *TunnelService) SaveTunnelMeta(name string, meta storage.TunnelMeta) error {
	if existing, err := t.tunnelStore.LoadMeta(name); err == nil && existing != nil {
		if meta.Protocol == "" {
			meta.Protocol = existing.Protocol
		}
	}
	return t.tunnelStore.SaveMeta(name, &meta)
}

// legacyLaunchAgent is the per-user LaunchAgent plist LockPlus wrote before
// login items moved to Wails' AutostartManager (SMAppService.mainApp).
const legacyLaunchAgent = "io.github.steiale.lockplus.gui.plist"

func removeLegacyLaunchAgent() (existed bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	err = os.Remove(filepath.Join(home, "Library", "LaunchAgents", legacyLaunchAgent))
	return err == nil
}

func (s *TunnelService) setAutostart(enabled bool) error {
	removeLegacyLaunchAgent()
	if s.app == nil {
		return fmt.Errorf("autostart: app not initialized")
	}
	if enabled {
		if err := s.app.Autostart.Enable(); err != nil {
			return fmt.Errorf("autostart: enable failed: %w", err)
		}
		return nil
	}
	if err := s.app.Autostart.Disable(); err != nil {
		return fmt.Errorf("autostart: disable failed: %w", err)
	}
	return nil
}

// migrateAutostart moves users who enabled launch-at-login under the old
// LaunchAgent plist over to the SMAppService login item. No-op otherwise.
func (s *TunnelService) migrateAutostart() {
	settings, err := s.settingsStore.Load()
	if err != nil || settings == nil || !settings.AutoStart {
		return
	}
	if !removeLegacyLaunchAgent() {
		return
	}
	if err := s.setAutostart(true); err != nil {
		slog.Warn("autostart migration failed", "error", err)
	}
}
