package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/steiale/wireguide/internal/config"
	"github.com/steiale/wireguide/internal/domain"
)

// TunnelStore manages .conf files on disk.
type TunnelStore struct {
	mu  sync.RWMutex
	dir string
}

// NewTunnelStore creates a TunnelStore for the given directory.
func NewTunnelStore(tunnelsDir string) *TunnelStore {
	return &TunnelStore{dir: tunnelsDir}
}

// Save writes a tunnel config to disk with 0600 permissions.
func (s *TunnelStore) Save(cfg *config.WireGuardConfig) error {
	if err := ValidateTunnelName(cfg.Name); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	content := config.Serialize(cfg)
	path := s.path(cfg.Name)

	// Atomic write: temp file + rename (prevents partial writes on crash).
	// Use os.CreateTemp to avoid predictable temp file names (symlink attacks).
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".wireguide-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := atomicRename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// Load reads a tunnel config from disk by name.
func (s *TunnelStore) Load(name string) (*config.WireGuardConfig, error) {
	if err := ValidateTunnelName(name); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	path := s.path(name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", name, err)
	}
	cfg.Name = name
	return cfg, nil
}

// Delete removes a tunnel config from disk.
func (s *TunnelStore) Delete(name string) error {
	if err := ValidateTunnelName(name); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// A tunnel is stored as either a .conf (WireGuard) or a .ovpn (OpenVPN)
	// file. Try the WireGuard path first; if it doesn't exist, remove the
	// OpenVPN file instead.
	path := s.path(name)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		err = os.Remove(s.ovpnPath(name))
	} else {
		// Also clean up an .ovpn file if one somehow coexists (best-effort).
		os.Remove(s.ovpnPath(name))
	}
	// Best-effort meta cleanup — never block tunnel deletion on a missing or
	// unwritable sidecar file.
	os.Remove(s.metaPath(name))
	return err
}

// Rename renames a tunnel from oldName to newName.
//
// Only `newName` is validated — `oldName` must already correspond to an
// existing file on disk, and filesystem escaping is handled by s.path().
// Validating oldName would strand users who have legacy files with
// characters the current ValidateTunnelName rejects (e.g. dots from the
// pre-Phase-0 era: `work.vpn.conf`), with no way to rename them out.
//
// Note: there is an intentional TOCTOU between exists() and Rename() — this
// is a single-user desktop app and the window is microseconds. If this ever
// becomes a multi-user service, switch to os.Link + os.Remove.
func (s *TunnelStore) Rename(oldName, newName string) error {
	if err := ValidateTunnelName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate that oldName resolves to a path within the tunnels directory
	// to prevent path traversal (e.g., oldName = "../../etc/shadow").
	oldPath := s.path(oldName)
	absOld, err := filepath.Abs(oldPath)
	if err != nil {
		return fmt.Errorf("invalid old name: %w", err)
	}
	absDir, err := filepath.Abs(s.dir)
	if err != nil {
		return fmt.Errorf("invalid directory: %w", err)
	}
	// Resolve symlinks so that a symlinked tunnels directory (or symlinked
	// path components in oldName) cannot bypass the HasPrefix check.
	if resolved, err := filepath.EvalSymlinks(absDir); err == nil {
		absDir = resolved
	}
	if resolved, err := filepath.EvalSymlinks(absOld); err == nil {
		absOld = resolved
	}
	if !strings.HasPrefix(absOld, absDir+string(filepath.Separator)) {
		return fmt.Errorf("tunnel name %q escapes tunnels directory", oldName)
	}

	if !s.exists(oldName) {
		return fmt.Errorf("tunnel %q does not exist", oldName)
	}
	if s.exists(newName) {
		return fmt.Errorf("tunnel %q already exists", newName)
	}

	// Rename the config file — .ovpn for OpenVPN tunnels, .conf for WireGuard.
	var srcCfg, dstCfg string
	if _, err := os.Stat(s.ovpnPath(oldName)); err == nil {
		srcCfg = s.ovpnPath(oldName)
		dstCfg = s.ovpnPath(newName)
	} else {
		srcCfg = oldPath
		dstCfg = s.path(newName)
	}
	if err := os.Rename(srcCfg, dstCfg); err != nil {
		return err
	}

	// Best-effort: rename the .meta.json sidecar as well.
	_ = os.Rename(s.metaPath(oldName), s.metaPath(newName))
	return nil
}

// List returns all tunnel names (without .conf extension).
func (s *TunnelStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".conf"):
			names = append(names, strings.TrimSuffix(name, ".conf"))
		case strings.HasSuffix(name, ".ovpn"):
			names = append(names, strings.TrimSuffix(name, ".ovpn"))
		}
	}
	return names, nil
}

// Exists checks if a tunnel with the given name exists.
func (s *TunnelStore) Exists(name string) bool {
	if err := ValidateTunnelName(name); err != nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.exists(name)
}

// exists is the internal lock-free version for use within already-locked methods.
// A tunnel exists if either its .conf (WireGuard) or .ovpn (OpenVPN) file is present.
func (s *TunnelStore) exists(name string) bool {
	if _, err := os.Stat(s.path(name)); err == nil {
		return true
	}
	if _, err := os.Stat(s.ovpnPath(name)); err == nil {
		return true
	}
	return false
}

// ImportFromContent parses content, assigns a name, and saves.
func (s *TunnelStore) ImportFromContent(name, content string) (*config.WireGuardConfig, error) {
	cfg, err := config.Parse(content)
	if err != nil {
		return nil, err
	}
	cfg.Name = name

	result := config.Validate(cfg)
	if !result.IsValid() {
		return nil, fmt.Errorf("validation failed: %s", strings.Join(result.ErrorMessages(), "; "))
	}

	if err := s.Save(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (s *TunnelStore) path(name string) string {
	return filepath.Join(s.dir, name+".conf")
}

// ovpnPath returns the on-disk path for a tunnel's raw .ovpn file.
func (s *TunnelStore) ovpnPath(name string) string {
	return filepath.Join(s.dir, name+".ovpn")
}

// SaveOVPN writes raw OpenVPN config content to disk with 0600 permissions,
// using the same atomic temp-file + rename pattern as Save().
func (s *TunnelStore) SaveOVPN(name, content string) error {
	if err := ValidateTunnelName(name); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.ovpnPath(name)
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".wireguide-ovpn-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := atomicRename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// LoadOVPN reads a tunnel's raw .ovpn content from disk.
func (s *TunnelStore) LoadOVPN(name string) (string, error) {
	if err := ValidateTunnelName(name); err != nil {
		return "", err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.ovpnPath(name))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// IsOVPN reports whether the stored tunnel is an OpenVPN tunnel (an .ovpn file
// exists for it).
func (s *TunnelStore) IsOVPN(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := os.Stat(s.ovpnPath(name))
	return err == nil
}

// TunnelMeta holds per-tunnel settings that live alongside the .conf file.
type TunnelMeta struct {
	AutoReconnect bool            `json:"auto_reconnect"`
	Notes         string          `json:"notes,omitempty"`
	Protocol      domain.Protocol `json:"protocol,omitempty"`
}

// metaPath returns the path for the tunnel's sidecar metadata file.
func (s *TunnelStore) metaPath(name string) string {
	return filepath.Join(s.dir, name+".meta.json")
}

// LoadMeta reads per-tunnel metadata. Returns empty defaults if not found.
func (s *TunnelStore) LoadMeta(name string) (*TunnelMeta, error) {
	data, err := os.ReadFile(s.metaPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return &TunnelMeta{Protocol: domain.ProtocolWireGuard}, nil
		}
		return nil, err
	}
	var m TunnelMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return &TunnelMeta{Protocol: domain.ProtocolWireGuard}, nil
	}
	// Backward compat: meta files written before the protocol field existed have
	// an empty value — treat those as WireGuard.
	m.Protocol = domain.NormalizeProtocol(m.Protocol)
	return &m, nil
}

// SaveMeta writes per-tunnel metadata atomically.
//
// Uses os.CreateTemp + Sync + Rename — the same pattern as Save() — instead of
// a predictable "<name>.tmp" suffix. The predictable suffix race-clobbered
// concurrent saves of the same tunnel and skipped fsync, so a crash during
// the rename window could leave a half-written meta file.
func (s *TunnelStore) SaveMeta(name string, meta *TunnelMeta) error {
	if err := ValidateTunnelName(name); err != nil {
		return err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	dst := s.metaPath(name)
	dir := filepath.Dir(dst)

	// CreateTemp gives us a unique randomized name so concurrent SaveMeta
	// calls for the same tunnel can't clobber each other's temp file.
	f, err := os.CreateTemp(dir, "."+name+".meta.*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return err
	}
	// Tighten perms after rename — CreateTemp uses 0600 already on most
	// platforms but we set it explicitly to match Save()'s contract.
	if err := os.Chmod(dst, 0600); err != nil {
		return err
	}
	return nil
}

// DeleteMeta removes the metadata sidecar file (called when tunnel is deleted).
func (s *TunnelStore) DeleteMeta(name string) {
	os.Remove(s.metaPath(name))
}
