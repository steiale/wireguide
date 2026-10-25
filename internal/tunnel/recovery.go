package tunnel

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/steiale/wireguide/internal/network"
)

// ActiveTunnelState is persisted while a tunnel is active; finding one at
// startup means the previous helper died without tearing the tunnel down.
// Older files carry extra fields (DNS snapshot, table/fwmark); they are
// ignored, the DNS journal in the network package supersedes them.
type ActiveTunnelState struct {
	TunnelName    string `json:"tunnel_name"`
	InterfaceName string `json:"interface_name"`
}

// tunnelStatesDir is the directory that stores per-tunnel state files.
const tunnelStatesDir = "tunnel-states"

// stateFileName returns the per-tunnel state file name inside tunnelStatesDir.
func stateFileName(tunnelName string) string {
	// Sanitize the tunnel name so it's safe as a file name.
	safe := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(tunnelName)
	return safe + ".json"
}

// SaveActiveState writes the active tunnel state to disk in a per-tunnel file.
func SaveActiveState(dataDir string, state *ActiveTunnelState) error {
	dir := filepath.Join(dataDir, tunnelStatesDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, stateFileName(state.TunnelName)), data, 0600)
}

// ClearActiveState removes the state file for a specific tunnel.
func ClearActiveState(dataDir string, tunnelName string) error {
	path := filepath.Join(dataDir, tunnelStatesDir, stateFileName(tunnelName))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ClearAllActiveStates removes all per-tunnel state files.
func ClearAllActiveStates(dataDir string) error {
	dir := filepath.Join(dataDir, tunnelStatesDir)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// LoadActiveState reads all active tunnel states.
func LoadActiveState(dataDir string) []*ActiveTunnelState {
	dir := filepath.Join(dataDir, tunnelStatesDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var states []*ActiveTunnelState
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var st ActiveTunnelState
		if err := json.Unmarshal(data, &st); err != nil {
			slog.Warn("corrupt tunnel state file, removing", "file", e.Name(), "error", err)
			os.Remove(filepath.Join(dir, e.Name()))
			continue
		}
		states = append(states, &st)
	}
	return states
}

// RecoverFromCrash removes routes left behind by tunnels of a previous
// helper process (the TUN device died with it, its bypass routes did not).
// Returns the recovered tunnel names. pf is handled by
// firewall.RecoverStaleState and DNS by network.RestoreDNSFromJournal.
func RecoverFromCrash(dataDir string) []string {
	states := LoadActiveState(dataDir)
	if len(states) == 0 {
		return nil
	}
	mgr := network.NewPlatformManager()
	var recovered []string
	for _, state := range states {
		slog.Warn("detected orphaned tunnel from previous crash",
			"tunnel", state.TunnelName, "interface", state.InterfaceName)
		if state.InterfaceName != "" {
			if err := mgr.Cleanup(state.InterfaceName); err != nil {
				slog.Warn("crash recovery: network cleanup failed", "error", err)
			}
		}
		recovered = append(recovered, state.TunnelName)
	}
	_ = ClearAllActiveStates(dataDir)
	return recovered
}
