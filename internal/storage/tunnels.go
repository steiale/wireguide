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

	return WriteFileAtomic(s.path(cfg.Name), []byte(config.Serialize(cfg)))
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

// Rename renames a tunnel. Only newName is validated so legacy names the
// current rules reject (e.g. "work.vpn") can still be renamed out; oldName
// is confined to the tunnels directory instead.
func (s *TunnelStore) Rename(oldName, newName string) error {
	if err := ValidateTunnelName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// A name without path separators can't leave the tunnels directory.
	if oldName == "" || oldName == "." || oldName == ".." || strings.ContainsAny(oldName, "/\x00") {
		return fmt.Errorf("tunnel name %q escapes tunnels directory", oldName)
	}
	oldPath := s.path(oldName)

	if !s.exists(oldName) {
		return fmt.Errorf("tunnel %q does not exist", oldName)
	}
	// On case-insensitive APFS a case-only rename finds the old file under
	// the new name; that is not a conflict.
	if s.exists(newName) && !s.sameTunnel(oldName, newName) {
		return fmt.Errorf("tunnel %q already exists", newName)
	}

	// Rename every config file present (.conf and .ovpn can coexist).
	_, ovpnErr := os.Stat(s.ovpnPath(oldName))
	ovpnExists := ovpnErr == nil
	_, confErr := os.Stat(oldPath)
	confExists := confErr == nil

	if !ovpnExists && !confExists {
		return fmt.Errorf("tunnel %q has no config file", oldName)
	}
	if ovpnExists {
		if err := os.Rename(s.ovpnPath(oldName), s.ovpnPath(newName)); err != nil {
			return err
		}
	}
	if confExists {
		if err := os.Rename(oldPath, s.path(newName)); err != nil {
			return err
		}
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
	// A tunnel can end up with both a .conf and .ovpn file coexisting (see
	// Rename's and Delete's comments — a legacy/weird coexistence case they
	// already clean up best-effort). Dedup here too so such a tunnel
	// surfaces once, not twice.
	seen := make(map[string]bool)
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		var base string
		switch {
		case strings.HasSuffix(name, ".conf"):
			base = strings.TrimSuffix(name, ".conf")
		case strings.HasSuffix(name, ".ovpn"):
			base = strings.TrimSuffix(name, ".ovpn")
		default:
			continue
		}
		if seen[base] {
			continue
		}
		seen[base] = true
		names = append(names, base)
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

// sameTunnel reports whether both names resolve to the same file (a
// case-only rename on a case-insensitive filesystem).
func (s *TunnelStore) sameTunnel(a, b string) bool {
	if !strings.EqualFold(a, b) {
		return false
	}
	for _, p := range []func(string) string{s.path, s.ovpnPath} {
		fa, errA := os.Stat(p(a))
		fb, errB := os.Stat(p(b))
		if errA == nil && errB == nil && os.SameFile(fa, fb) {
			return true
		}
	}
	return false
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

// SaveOVPN writes raw OpenVPN config content to disk with 0600 permissions.
func (s *TunnelStore) SaveOVPN(name, content string) error {
	if err := ValidateTunnelName(name); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return WriteFileAtomic(s.ovpnPath(name), []byte(content))
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

// LoadMeta reads per-tunnel metadata, defaulting when missing or corrupt.
// Protocol is OpenVPN whenever an .ovpn file exists (authoritative over the
// meta, which may be missing for migrated tunnels), else WireGuard.
func (s *TunnelStore) LoadMeta(name string) (*TunnelMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := &TunnelMeta{}
	data, err := os.ReadFile(s.metaPath(name))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil && json.Unmarshal(data, m) != nil {
		m = &TunnelMeta{}
	}
	m.Protocol = domain.NormalizeProtocol(m.Protocol)
	if _, err := os.Stat(s.ovpnPath(name)); err == nil {
		m.Protocol = domain.ProtocolOpenVPN
	}
	return m, nil
}

// SaveMeta writes per-tunnel metadata atomically.
func (s *TunnelStore) SaveMeta(name string, meta *TunnelMeta) error {
	if err := ValidateTunnelName(name); err != nil {
		return err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	// Same lock as Rename, which moves this file.
	s.mu.Lock()
	defer s.mu.Unlock()

	return WriteFileAtomic(s.metaPath(name), data)
}
