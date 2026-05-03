package app

import (
	"sync/atomic"

	"github.com/steiale/wireguide/internal/wifi"
)

// wifiRulesNotifier is set by internal/gui at startup so the app package
// (Wails-bound) can hand new rules to the live wifi.Monitor without
// importing internal/gui (which would create an import cycle). Same pattern
// as guiLogLevelSetter in settings_ops.go.
var wifiRulesNotifier atomic.Value // stores func(*wifi.Rules)

// SetWifiRulesNotifier is called once from internal/gui.Run to register the
// monitor-update hook. Safe to call before NewTunnelService.
func SetWifiRulesNotifier(f func(*wifi.Rules)) {
	wifiRulesNotifier.Store(f)
}

func getWifiRulesNotifier() func(*wifi.Rules) {
	if v := wifiRulesNotifier.Load(); v != nil {
		return v.(func(*wifi.Rules))
	}
	return nil
}

// GetWifiRules returns the persisted Wi-Fi auto-connect rules. Defaults
// (feature disabled, empty maps) on first run.
func (s *TunnelService) GetWifiRules() (*wifi.Rules, error) {
	return s.wifiRulesStore.Load()
}

// SaveWifiRules persists the rules and pushes them to the live monitor so
// the next SSID poll uses the new configuration without an app restart.
func (s *TunnelService) SaveWifiRules(rules wifi.Rules) error {
	// Normalise nil collections so they never round-trip back to the
	// frontend as `null` — Svelte's bindings would crash on subsequent
	// reads of `rules.ssid_tunnel_map[ssid]`.
	if rules.SSIDTunnelMap == nil {
		rules.SSIDTunnelMap = make(map[string]string)
	}
	if rules.TrustedSSIDs == nil {
		rules.TrustedSSIDs = []string{}
	}
	if err := s.wifiRulesStore.Save(&rules); err != nil {
		return err
	}
	if fn := getWifiRulesNotifier(); fn != nil {
		// Hand a copy so the monitor's mutex-protected pointer can't be
		// mutated by a later SaveWifiRules call without going through Save.
		copy := rules
		fn(&copy)
	}
	return nil
}

// GetCurrentSSID returns the SSID the user is currently connected to,
// or "" if not connected to a Wi-Fi network. Read on demand — no IPC, no
// state. The Wi-Fi Rules UI uses this for a live "Currently on:" badge.
func (s *TunnelService) GetCurrentSSID() string {
	return wifi.CurrentSSID()
}
