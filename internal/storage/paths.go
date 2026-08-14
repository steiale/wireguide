package storage

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
)

const appName = "lockplus"

// legacyAppName was the app's data-directory name before the WireGuide+ →
// LockPlus rename (v1.0.57). Kept around solely so MigrateLegacyTunnels can
// find configs left behind by the old install.
const legacyAppName = "wireguide-plus"

// canWriteDir tests whether the current process can create files in dir by
// writing and immediately removing a temp file. Used by EnsureDirs to
// distinguish "can't chmod but can still use" from "truly inaccessible".
// Uses a randomized name (os.CreateTemp) rather than a fixed one — the GUI
// and the privileged helper both call EnsureDirs at startup and could race
// on create/remove of the same fixed-name probe file otherwise.
func canWriteDir(dir string) bool {
	f, err := os.CreateTemp(dir, ".wireguide-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// Paths holds all OS-specific directory paths for the application.
type Paths struct {
	ConfigDir  string // App settings (config.json)
	TunnelsDir string // .conf files
	LogsDir    string // Log files
	DataDir    string // Daemon state / recovery journal (system-level)
}

// GetPaths returns OS-specific paths for the application.
func GetPaths() (*Paths, error) {
	var p Paths

	switch runtime.GOOS { //nolint:exhaustive
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		appSupport := filepath.Join(home, "Library", "Application Support", appName)
		p.ConfigDir = appSupport
		p.TunnelsDir = filepath.Join(appSupport, "tunnels")
		p.LogsDir = filepath.Join(home, "Library", "Logs", appName)
		p.DataDir = filepath.Join("/Library", "Application Support", appName)

	case "linux":
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			configHome = filepath.Join(home, ".config")
		}
		p.ConfigDir = filepath.Join(configHome, appName)
		p.TunnelsDir = filepath.Join(configHome, appName, "tunnels")

		dataHome := os.Getenv("XDG_DATA_HOME")
		if dataHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			dataHome = filepath.Join(home, ".local", "share")
		}
		p.LogsDir = filepath.Join(dataHome, appName, "logs")
		p.DataDir = filepath.Join("/var", "lib", appName)

	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		p.ConfigDir = filepath.Join(appData, appName)
		p.TunnelsDir = filepath.Join(appData, appName, "tunnels")
		p.LogsDir = filepath.Join(appData, appName, "logs")

		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		p.DataDir = filepath.Join(programData, appName)

	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	return &p, nil
}

// EnsureDirs creates all necessary directories if they don't exist.
// ConfigDir and TunnelsDir use 0700 to prevent other users from listing
// config filenames on multi-user systems. LogsDir and DataDir use 0700 as well.
//
// DataDir may require root permissions (e.g. /var/lib/wireguide on Linux,
// /Library/Application Support/wireguide on macOS). If creation fails due
// to insufficient privileges, the error is logged as a warning instead of
// failing the entire startup — the helper process will create it when running
// as root.
func (p *Paths) EnsureDirs() error {
	userDirs := []string{p.ConfigDir, p.TunnelsDir, p.LogsDir}
	for _, dir := range userDirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		// Enforce permissions even if the directory already existed with
		// wider permissions (e.g., 0755 from a previous version).
		if err := os.Chmod(dir, 0700); err != nil {
			// Chmod fails when the directory is owned by another user (e.g.
			// root created it during a previous helper spawn). As long as
			// we can actually write to it, proceed with a warning — crashing
			// the entire app over a permission tightening failure on a
			// directory we can still use is worse than running with 0755.
			if canWriteDir(dir) {
				slog.Warn("cannot tighten dir permissions (owned by another user)",
					"dir", dir, "error", err)
			} else {
				return fmt.Errorf("directory %s exists but is not writable: %w", dir, err)
			}
		}
	}
	// DataDir may require elevated privileges; warn instead of failing.
	if p.DataDir != "" {
		if err := os.MkdirAll(p.DataDir, 0700); err != nil {
			slog.Warn("cannot create DataDir (may need root)", "dir", p.DataDir, "error", err)
		} else if err := os.Chmod(p.DataDir, 0700); err != nil {
			slog.Warn("cannot set DataDir permissions", "dir", p.DataDir, "error", err)
		}
	}
	return nil
}

// MigrateLegacyTunnels copies tunnel configs from the pre-rename
// ~/Library/Application Support/wireguide-plus/tunnels directory into the
// current TunnelsDir, if TunnelsDir is empty and the legacy directory has
// files. It only ever copies — never deletes or moves the legacy directory —
// so a failed or partial migration can always be retried or inspected by
// hand. Call this once at startup, after EnsureDirs and before the
// TunnelStore is constructed.
//
// Why this exists: upgrading from WireGuide+ to LockPlus (Homebrew cask
// rename, v1.0.57) silently orphaned every tunnel a user had configured,
// since the macOS Application Support directory name changed. This bit
// real users on real machines with no way to recover except manual shell
// surgery — this migration makes the upgrade path self-healing.
func (p *Paths) MigrateLegacyTunnels() {
	if runtime.GOOS != "darwin" {
		return
	}
	if entries, err := os.ReadDir(p.TunnelsDir); err == nil && len(entries) > 0 {
		return // already has tunnels — never overwrite existing data
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	legacyDir := filepath.Join(home, "Library", "Application Support", legacyAppName, "tunnels")
	legacyEntries, err := os.ReadDir(legacyDir)
	if err != nil || len(legacyEntries) == 0 {
		return
	}
	slog.Info("migrating tunnels from legacy wireguide-plus data dir",
		"from", legacyDir, "to", p.TunnelsDir, "count", len(legacyEntries))
	for _, e := range legacyEntries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(legacyDir, e.Name())
		dst := filepath.Join(p.TunnelsDir, e.Name())
		data, err := os.ReadFile(src)
		if err != nil {
			slog.Warn("legacy tunnel migration: read failed", "file", src, "error", err)
			continue
		}
		if err := os.WriteFile(dst, data, 0600); err != nil {
			slog.Warn("legacy tunnel migration: write failed", "file", dst, "error", err)
		}
	}
}
