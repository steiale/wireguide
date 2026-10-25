package storage

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

// Paths holds the application's directories.
type Paths struct {
	ConfigDir  string // App settings (config.json)
	TunnelsDir string // .conf files
	LogsDir    string // Log files
	DataDir    string // Daemon state / recovery journal (system-level)
}

// GetPaths returns the application's paths.
func GetPaths() (*Paths, error) {
	var p Paths

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	appSupport := filepath.Join(home, "Library", "Application Support", appName)
	p.ConfigDir = appSupport
	p.TunnelsDir = filepath.Join(appSupport, "tunnels")
	p.LogsDir = filepath.Join(home, "Library", "Logs", appName)
	p.DataDir = filepath.Join("/Library", "Application Support", appName)

	return &p, nil
}

// EnsureDirs creates all necessary directories if they don't exist.
// ConfigDir and TunnelsDir use 0700 to prevent other users from listing
// config filenames on multi-user systems. LogsDir and DataDir use 0700 as well.
//
// DataDir (/Library/Application Support/lockplus) needs root; failing to
// create it is only a warning, the helper creates it.
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

// MigrateLegacyTunnels copies tunnel files from the pre-rename
// ~/Library/Application Support/wireguide-plus/tunnels (the v1.0.57 rename
// orphaned them) into TunnelsDir. It never deletes or overwrites, skips temp
// files, and copies whatever is still missing, so an interrupted migration
// resumes on the next start; a marker written after a clean pass stops it
// from resurrecting tunnels the user later deleted. Call after EnsureDirs.
func (p *Paths) MigrateLegacyTunnels() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	migrateTunnels(filepath.Join(home, "Library", "Application Support", legacyAppName, "tunnels"), p.TunnelsDir)
}

// migratedMarker in TunnelsDir records a completed legacy migration.
const migratedMarker = ".legacy-migrated"

func migrateTunnels(legacyDir, dstDir string) {
	marker := filepath.Join(dstDir, migratedMarker)
	if _, err := os.Stat(marker); err == nil {
		return
	}
	entries, err := os.ReadDir(legacyDir)
	if err != nil {
		return
	}
	clean := true
	defer func() {
		if clean {
			_ = os.WriteFile(marker, nil, 0600)
		}
	}()
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || strings.HasSuffix(name, ".tmp") || strings.HasPrefix(name, ".") {
			continue
		}
		dst := filepath.Join(dstDir, name)
		if _, err := os.Lstat(dst); err == nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(legacyDir, name))
		if err != nil {
			slog.Warn("legacy tunnel migration: read failed", "file", name, "error", err)
			clean = false
			continue
		}
		// O_EXCL: never clobber a file that appeared meanwhile.
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			slog.Warn("legacy tunnel migration: create failed", "file", name, "error", err)
			clean = false
			continue
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = os.Remove(dst)
			slog.Warn("legacy tunnel migration: write failed", "file", name, "error", werr)
			clean = false
			continue
		}
		slog.Info("migrated legacy tunnel file", "file", name)
	}
}
