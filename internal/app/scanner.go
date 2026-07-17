package app

import (
	"os"
	"path/filepath"
	"runtime"
)

// FoundConfig is a WireGuard .conf found on the filesystem.
type FoundConfig struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// scanSystemWireGuardConfigs scans well-known locations for .conf files
// not already present in existingNames.
func scanSystemWireGuardConfigs(existingNames map[string]bool) []FoundConfig {
	home, _ := os.UserHomeDir()

	var dirs []string
	switch runtime.GOOS {
	case "darwin":
		dirs = []string{
			"/etc/wireguard",
			"/usr/local/etc/wireguard",
			filepath.Join(home, "Library", "Application Support", "wireguide", "tunnels"),
		}
	case "linux":
		dirs = []string{
			"/etc/wireguard",
			filepath.Join(home, ".config", "wireguide", "tunnels"),
		}
	case "windows":
		pf := os.Getenv("PROGRAMFILES")
		if pf == "" {
			pf = `C:\Program Files`
		}
		dirs = []string{filepath.Join(pf, "WireGuard", "Data", "Configurations")}
	}

	var found []FoundConfig
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			// stripKnownTunnelExt matches case-insensitively AND strips
			// case-insensitively — plain strings.TrimSuffix(name, ".conf")
			// only strips an exact-case match, so "Foo.CONF" passed the old
			// HasSuffix(ToLower(...)) check but came back from TrimSuffix
			// unchanged, leaving the dot+extension in "name" and failing
			// tunnel name validation on every subsequent import attempt.
			name, ext := stripKnownTunnelExt(e.Name())
			if ext != ".conf" {
				continue
			}
			if existingNames[name] {
				continue
			}
			found = append(found, FoundConfig{Name: name, Path: filepath.Join(dir, e.Name())})
		}
	}
	return found
}
