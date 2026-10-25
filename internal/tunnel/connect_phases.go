package tunnel

import (
	"log/slog"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/network"
)

// connectPhases brings a tunnel up. Called from Manager.Connect WITHOUT
// m.mu held. Returns the engine on success; on failure, partial state is
// rolled back before the error is returned.
//
// Steps: engine (TUN + wireguard-go) → crash-recovery record → MTU →
// address → up → routes (incl. endpoint bypass) → DNS.
//
// Pre/PostUp/Down scripts are parsed but never executed (security hardening).
func (m *Manager) connectPhases(cfg *domain.WireGuardConfig, netMgr network.NetworkManager) (*Engine, error) {
	fullTunnel := cfg.IsFullTunnel()

	factory := m.engineFactory
	if factory == nil {
		factory = NewEngine
	}
	engine, err := factory(cfg)
	if err != nil {
		return nil, newTunnelError(ErrEngineCreation, "creating engine", err)
	}
	ifaceName := engine.InterfaceName()

	// Record the tunnel before touching routes or DNS, so a crash at any
	// later point is cleaned up at the next helper start. (DNS itself is
	// recovered from the network package's journal.)
	if err := SaveActiveState(m.dataDir, &ActiveTunnelState{TunnelName: cfg.Name, InterfaceName: ifaceName}); err != nil {
		slog.Warn("failed to persist crash recovery state", "error", err)
	}

	// rollback undoes partial state; cleanup errors are logged, the primary
	// failure is what gets reported.
	rollback := func(primary error) error {
		if err := netMgr.Cleanup(ifaceName); err != nil {
			slog.Warn("rollback: network cleanup failed", "error", err)
		}
		engine.Close()
		_ = ClearActiveState(m.dataDir, cfg.Name)
		return primary
	}

	// MTU 0 lets the platform auto-detect (upstream MTU - 80); never force
	// 1420 here, it would be wrong on PPPoE or jumbo-frame links.
	if err := netMgr.SetMTU(ifaceName, cfg.Interface.MTU); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "setting MTU", err))
	}
	if err := netMgr.AssignAddress(ifaceName, cfg.Interface.Address); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "assigning address", err))
	}
	if err := netMgr.BringUp(ifaceName); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "bringing up interface", err))
	}

	// Pass the endpoint IPs NewEngine already resolved: resolving after the
	// split routes exist would send the query through the tunnel itself.
	var allAllowedIPs []string
	for _, peer := range cfg.Peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}
	if err := netMgr.AddRoutes(ifaceName, allAllowedIPs, fullTunnel, engine.ResolvedEndpointIPs(), cfg.Interface.Table); err != nil {
		return nil, rollback(newTunnelError(ErrNetwork, "adding routes", err))
	}

	// DNS failure is fatal when DNS is configured (as in wg-quick): silently
	// staying on the ISP resolver would be a leak. The network package
	// merges this tunnel's entries with every other active tunnel's.
	if len(cfg.Interface.DNS) > 0 {
		if err := netMgr.SetDNS(ifaceName, cfg.Interface.DNS); err != nil {
			return nil, rollback(newTunnelError(ErrNetwork, "setting DNS", err))
		}
	}

	slog.Info("tunnel connected",
		"name", cfg.Name,
		"interface", ifaceName,
		"full_tunnel", fullTunnel)
	return engine, nil
}

// disconnectPhases tears an active tunnel down. Called WITHOUT m.mu held.
// Best-effort: errors are logged, partial teardown beats none.
func (m *Manager) disconnectPhases(cfg *domain.WireGuardConfig, engine *Engine, netMgr network.NetworkManager) {
	ifaceName := engine.InterfaceName()
	// Each tunnel has its own netMgr, so this only touches this tunnel's
	// routes; its DNS hold is released and the remaining tunnels' DNS is
	// re-applied by the network package.
	if netMgr != nil {
		if err := netMgr.Cleanup(ifaceName); err != nil {
			slog.Warn("network cleanup failed", "tunnel", cfg.Name, "error", err)
		}
	}
	engine.Close()
	_ = ClearActiveState(m.dataDir, cfg.Name)
	slog.Info("tunnel disconnected", "name", cfg.Name)
}
