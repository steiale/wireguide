package app

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/korjwl1/wireguide/internal/autostart"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/update"
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
	// Read the previous state first so we only (un)install the autostart
	// entry when the user actually toggles it. This avoids rewriting the
	// LaunchAgent plist / desktop file on every unrelated setting change.
	prev, _ := s.settingsStore.Load()

	if err := s.settingsStore.Save(settings); err != nil {
		return err
	}

	if prev == nil || prev.AutoStart != settings.AutoStart {
		if settings.AutoStart {
			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("autostart: cannot resolve exe path: %w", err)
			}
			if err := autostart.InstallAutostart(exe); err != nil {
				return fmt.Errorf("autostart: install failed: %w", err)
			}
		} else {
			if err := autostart.RemoveAutostart(); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("autostart: remove failed: %w", err)
			}
		}
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

// --- Firewall toggles (go through helper) ---

// SetKillSwitch asks the helper to enable or disable the firewall kill switch.
func (s *TunnelService) SetKillSwitch(enabled bool) error {
	return s.call(ipc.MethodSetKillSwitch, ipc.KillSwitchRequest{Enabled: enabled}, nil)
}

// SetDNSProtection asks the helper to lock DNS to the active tunnel's servers.
// When enabling, we look up the active tunnel's DNS list from local storage
// and pass it along (the helper never touches user-space storage).
func (s *TunnelService) SetDNSProtection(enabled bool) error {
	var dnsServers []string
	if enabled {
		var active ipc.StringResponse
		if err := s.call(ipc.MethodActiveName, nil, &active); err != nil {
			return fmt.Errorf("cannot verify tunnel state: %w", err)
		}
		if active.Value != "" {
			if cfg, err := s.tunnelStore.Load(active.Value); err == nil {
				dnsServers = cfg.Interface.DNS
			}
		}
	}
	return s.call(ipc.MethodSetDNSProtection, ipc.DNSProtectionRequest{
		Enabled:    enabled,
		DNSServers: dnsServers,
	}, nil)
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
	"https://github.com/korjwl1/wireguide/releases/latest": {},
	// Repo home / issues / license — linked from the Settings "About" panel.
	// The frontend currently points at the steiale/wireguide org; both
	// owners' canonical pages are listed so the existing UI keeps working
	// without silently breaking.
	"https://github.com/steiale/wireguide":                       {},
	"https://github.com/steiale/wireguide/issues":                {},
	"https://github.com/steiale/wireguide/blob/main/LICENSE":     {},
	"https://github.com/steiale/wireguide/releases/latest":       {},
	"https://github.com/korjwl1/wireguide":                       {},
	"https://github.com/korjwl1/wireguide/issues":                {},
	"https://github.com/korjwl1/wireguide/blob/main/LICENSE":     {},
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

// CheckForUpdate queries GitHub for a newer release.
func (s *TunnelService) CheckForUpdate() (*update.UpdateInfo, error) {
	return update.CheckForUpdate()
}

// RunUpdate performs the update. If installed via Homebrew, runs brew upgrade.
// Otherwise downloads and installs directly from GitHub Releases.
func (s *TunnelService) RunUpdate(info *update.UpdateInfo) error {
	if info == nil || !info.Available {
		return fmt.Errorf("no update available")
	}

	if runtime.GOOS == "darwin" && update.IsBrewInstall() {
		brewBin := update.BrewPath()
		// Update tap first to ensure latest cask version is fetched
		slog.Info("update: running brew update", "brew", brewBin)
		if out, err := exec.Command(brewBin, "update").CombinedOutput(); err != nil {
			slog.Warn("brew update failed, continuing with upgrade", "error", err, "output", string(out))
		}
		slog.Info("update: running brew upgrade --cask wireguide")
		cmd := exec.Command(brewBin, "upgrade", "--cask", "wireguide")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("brew upgrade failed: %w (%s)", err, string(out))
		}
		// postflight in the cask handles killall + relaunch
		return nil
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
			_ = s.app.Browser.OpenURL("https://github.com/korjwl1/wireguide/releases/latest")
		} else {
			_ = exec.Command("open", "https://github.com/korjwl1/wireguide/releases/latest").Run()
		}
		return fmt.Errorf("download/verify failed: %w", err)
	}
	if err := update.Install(dlPath, info); err != nil {
		return fmt.Errorf("install (reveal): %w", err)
	}
	return nil
}

// ScanForWireGuardConfigs returns existing WireGuard configs found on the
// filesystem that haven't been imported into WireGuide+ yet.
func (t *TunnelService) ScanForWireGuardConfigs() []FoundConfig {
	list, _ := t.tunnelStore.List()
	existing := make(map[string]bool, len(list))
	for _, n := range list {
		existing[n] = true
	}
	return scanSystemWireGuardConfigs(existing)
}

// ImportFoundConfigs reads and imports the .conf files at the given absolute
// paths. Returns per-file results reusing the ZipImportResult shape.
func (t *TunnelService) ImportFoundConfigs(paths []string) []ZipImportResult {
	var results []ZipImportResult
	for _, p := range paths {
		name := strings.TrimSuffix(filepath.Base(p), ".conf")
		data, err := os.ReadFile(p)
		if err != nil {
			results = append(results, ZipImportResult{Name: name, Error: err.Error()})
			continue
		}
		if _, err := t.tunnelStore.ImportFromContent(name, string(data)); err != nil {
			results = append(results, ZipImportResult{Name: name, Error: err.Error()})
		} else {
			results = append(results, ZipImportResult{Name: name})
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

// SaveTunnelMeta persists per-tunnel metadata.
func (t *TunnelService) SaveTunnelMeta(name string, meta storage.TunnelMeta) error {
	return t.tunnelStore.SaveMeta(name, &meta)
}
