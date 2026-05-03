package storage

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/wifi"
)

// WifiRulesStore manages the wifi_rules.json file.
//
// Lives next to settings (config.json) in ConfigDir. We deliberately keep
// this separate from the main Settings struct so unrelated changes (theme,
// log level, etc.) don't rewrite the wifi rules file, and so the rules can
// evolve independently in shape without bumping a global settings version.
type WifiRulesStore struct {
	mu   sync.Mutex
	path string
}

// NewWifiRulesStore creates a store for the given config directory.
func NewWifiRulesStore(configDir string) *WifiRulesStore {
	return &WifiRulesStore{
		path: filepath.Join(configDir, "wifi_rules.json"),
	}
}

// Load reads rules from disk. Returns defaults (feature disabled) if the
// file doesn't exist or is unreadable / corrupt — never blocks startup.
func (s *WifiRulesStore) Load() (*wifi.Rules, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return wifi.DefaultRules(), nil
		}
		return nil, err
	}
	rules := wifi.DefaultRules()
	if err := json.Unmarshal(data, rules); err != nil {
		// Same corruption-recovery pattern as SettingsStore: back up the
		// bad file with a timestamped suffix so multiple corruptions don't
		// overwrite each other, log a warning, and fall back to defaults.
		backup := fmt.Sprintf("%s.corrupt.%s", s.path, time.Now().UTC().Format("20060102T150405Z"))
		slog.Warn("wifi rules file is corrupt, falling back to defaults",
			"path", s.path, "backup", backup, "error", err)
		_ = os.Rename(s.path, backup)
		return wifi.DefaultRules(), nil
	}
	// Defensive: a JSON file written without the map (or with `null`) would
	// give us a nil SSIDTunnelMap, which crashes Action() when callers do
	// `_, ok := r.SSIDTunnelMap[ssid]` on a nil map (read is fine, but the
	// frontend round-trips through this struct and may try to write into it
	// after Load). Initialise to an empty map.
	if rules.SSIDTunnelMap == nil {
		rules.SSIDTunnelMap = make(map[string]string)
	}
	return rules, nil
}

// Save writes rules to disk atomically (temp file + rename, 0600 perms).
func (s *WifiRulesStore) Save(rules *wifi.Rules) error {
	if rules == nil {
		return fmt.Errorf("wifi rules: cannot save nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(s.path), ".wireguide-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
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
	if err := atomicRename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
