package helper

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/steiale/wireguide/internal/config"
	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/ovpn"
	"github.com/steiale/wireguide/internal/storage"
	"github.com/steiale/wireguide/internal/tunnel"
	"github.com/steiale/wireguide/internal/update"
)

// registerHandlers binds every RPC method to a Helper method. Splitting the
// handlers into named methods (vs inline closures) makes them directly unit
// testable — `handler := &Helper{manager: mockMgr}; handler.handleConnect(...)`.
func (h *Helper) registerHandlers() {
	h.server.Handle(ipc.MethodPing, h.handlePing)
	// Only honor MethodShutdown when running outside launchd. As a
	// LaunchDaemon (KeepAlive=true) the OS owns the helper's lifecycle —
	// obeying a GUI Shutdown causes launchd to immediately respawn us, the
	// next GUI quit sends Shutdown again, and we end up in a crash loop.
	if !isDaemon() {
		h.server.Handle(ipc.MethodShutdown, h.handleShutdown)
	}
	h.server.Handle(ipc.MethodSetLogLevel, h.handleSetLogLevel)
	h.server.Handle(ipc.MethodConnect, h.handleConnect)
	h.server.Handle(ipc.MethodDisconnect, h.handleDisconnect)
	h.server.Handle(ipc.MethodStatus, h.handleStatus)
	h.server.Handle(ipc.MethodIsConnected, h.handleIsConnected)
	h.server.Handle(ipc.MethodActiveName, h.handleActiveName)
	h.server.Handle(ipc.MethodActiveTunnels, h.handleActiveTunnels)
	h.server.Handle(ipc.MethodSetKillSwitch, h.handleSetKillSwitch)
	h.server.Handle(ipc.MethodSetDNSProtection, h.handleSetDNSProtection)
	h.server.Handle(ipc.MethodSetHealthCheck, h.handleSetHealthCheck)
	h.server.Handle(ipc.MethodSetPinInterface, h.handleSetPinInterface)
	h.server.Handle(ipc.MethodFeedCredentials, h.handleFeedCredentials)
}

func (h *Helper) handleSetLogLevel(params json.RawMessage) (interface{}, error) {
	var req ipc.SetLogLevelRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	lvl := parseLevel(req.Level)
	h.logLevel.Set(lvl)
	slog.Info("log level changed", "level", req.Level)
	return ipc.Empty{}, nil
}

func (h *Helper) handlePing(params json.RawMessage) (interface{}, error) {
	// Best-effort lookup of the running binary path. Used by the GUI to
	// detect a stale daemon (old combined GUI binary running in --helper
	// mode after an upgrade that the user didn't grant admin rights to).
	exe, _ := os.Executable()
	return ipc.PingResponse{
		Version:    ipc.ProtocolVersion,
		AppVersion: update.CurrentVersion(),
		PID:        os.Getpid(),
		BinaryPath: exe,
	}, nil
}

func (h *Helper) handleShutdown(params json.RawMessage) (interface{}, error) {
	go func() {
		time.Sleep(100 * time.Millisecond) // let the response go out first
		h.shutdown()
	}()
	return ipc.Empty{}, nil
}

func (h *Helper) handleConnect(params json.RawMessage) (interface{}, error) {
	// Serialize Connect calls so two GUIs can't race on activeCfg.
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	var req ipc.ConnectRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}

	// OpenVPN path: route to the OpenVPN manager. WireGuard logic below is
	// unchanged. NormalizeProtocol treats an empty protocol as WireGuard so
	// legacy GUI builds keep working.
	if domain.NormalizeProtocol(req.Protocol) == domain.ProtocolOpenVPN {
		return h.connectOpenVPN(&req)
	}

	if req.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	// The tunnel name flows straight into filesystem paths (state files,
	// UAPI socket lookups) — reject anything ValidateTunnelName wouldn't
	// accept as a saved tunnel's name, same as the storage layer requires
	// on save/rename. This helper runs as root and must not trust the
	// caller's name to already be safe (see the equivalent check on the
	// OpenVPN path in connectOpenVPN, added for the same reason).
	if err := storage.ValidateTunnelName(req.Config.Name); err != nil {
		return nil, fmt.Errorf("invalid tunnel name: %w", err)
	}
	// Re-validate config server-side (don't trust client).
	if result := config.Validate(req.Config); !result.IsValid() {
		return nil, fmt.Errorf("invalid config: %s", strings.Join(result.ErrorMessages(), "; "))
	}

	// Log if the config contains scripts — they are parsed but ignored.
	if req.Config.HasScripts() {
		slog.Info("config contains Pre/PostUp/Down scripts; ignoring (not supported in GUI client)",
			"tunnel", req.Config.Name)
	}

	// Check for routing conflicts with existing interfaces (Tailscale etc).
	// Log warnings but don't block — users can override via UI.
	var allowedIPs []string
	for _, peer := range req.Config.Peers {
		allowedIPs = append(allowedIPs, peer.AllowedIPs...)
	}
	if conflicts, err := tunnel.CheckConflicts(allowedIPs); err == nil && len(conflicts) > 0 {
		for _, c := range conflicts {
			slog.Warn("routing conflict detected",
				"interface", c.InterfaceName,
				"owner", c.Owner,
				"overlaps", c.OverlappingIPs)
		}
	}

	// M6: Early-return if this exact tunnel is already active. The manager
	// would also catch this and return ErrAlreadyConnected, but checking up
	// front avoids the unnecessary mutate-then-rollback dance on activeCfgs
	// and lets the GUI treat it as a no-op via a typed error code.
	h.mu.Lock()
	_, alreadyCached := h.activeCfgs[req.Config.Name]
	h.mu.Unlock()
	if alreadyCached {
		for _, n := range h.manager.ActiveTunnels() {
			if n == req.Config.Name {
				return nil, &ipc.CodedError{
					Code:    ipc.ErrCodeAlreadyConnected,
					Message: fmt.Sprintf("tunnel %q is already connected", req.Config.Name),
				}
			}
		}
	}

	// Cache the active config BEFORE dispatching to the manager, so that if
	// the reconnect monitor fires during Connect() it sees the new config
	// (not nil or the previous one). Roll back on failure.
	//
	// H1: snapshot autoReconnect alongside activeCfgs so that a failed
	// reconnect rollback restores the user's auto-reconnect preference,
	// not the default zero value.
	h.mu.Lock()
	prevCfgs := h.copyActiveCfgs()
	prevAutoReconnect, prevHadAutoReconnect := h.autoReconnect[req.Config.Name]
	h.activeCfgs[req.Config.Name] = req.Config
	h.autoReconnect[req.Config.Name] = req.AutoReconnect
	h.mu.Unlock()

	if err := h.manager.Connect(req.Config); err != nil {
		h.mu.Lock()
		delete(h.activeCfgs, req.Config.Name)
		delete(h.autoReconnect, req.Config.Name)
		// Restore previous config + autoReconnect if there was one.
		if prev, ok := prevCfgs[req.Config.Name]; ok {
			h.activeCfgs[req.Config.Name] = prev
		}
		if prevHadAutoReconnect {
			h.autoReconnect[req.Config.Name] = prevAutoReconnect
		}
		h.mu.Unlock()
		return nil, err
	}
	h.refreshKillSwitchIfEnabled("wg-connect", req.Config.Name)
	return ipc.Empty{}, nil
}

func (h *Helper) handleDisconnect(params json.RawMessage) (interface{}, error) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	// Parse optional tunnel name from request. Genuinely empty params means
	// a legacy caller with no tunnel name — disconnect the first active
	// tunnel (backward compat). But params that ARE present and fail to
	// unmarshal are a malformed request, not "no name given" — silently
	// falling through to the nameless path previously meant a garbled
	// request tore down an arbitrary (first) tunnel instead of surfacing
	// the actual error.
	var tunnelName string
	if len(params) > 0 {
		var req ipc.DisconnectRequest
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, fmt.Errorf("invalid disconnect request: %w", err)
		}
		tunnelName = req.TunnelName
	}

	// Cancel any in-flight reconnect backoff first — otherwise the monitor
	// could wake up seconds after the user clicked Disconnect and re-connect
	// against their wishes. Scoped to tunnelName so disconnecting one tunnel
	// doesn't abort a different tunnel's still-in-progress recovery; the
	// legacy nameless-disconnect path (tunnelName == "") still cancels
	// every active retry, matching what it actually tears down.
	if h.monitor != nil {
		h.monitor.CancelRetry(tunnelName)
	}

	// OpenVPN tunnels are tracked separately. If the named tunnel is an active
	// OpenVPN tunnel, route the disconnect there and return.
	if tunnelName != "" && h.ovpnManager != nil {
		for _, n := range h.ovpnManager.ActiveTunnelNames() {
			if n == tunnelName {
				// Clear BEFORE tearing down, same reasoning as the WireGuard
				// path below: a concurrent "died unexpectedly" callback
				// (ovpn.Manager.SetOnDied) must never see this tunnel as
				// still wanting auto-reconnect once the user has explicitly
				// asked to disconnect it.
				h.mu.Lock()
				delete(h.activeOVPNCfgs, tunnelName)
				delete(h.autoReconnect, tunnelName)
				h.mu.Unlock()
				err := h.ovpnManager.Disconnect(tunnelName)
				if h.monitor != nil {
					// Cancel again in case onOVPNDied's NotifyTunnelDied
					// registered a retry in the window between the
					// CancelRetry at the top of this function and the
					// autoReconnect clear just above — without this, an
					// orphaned retry would keep calling reconnectFn for a
					// tunnel with no cached config anymore, failing forever
					// and flapping the kill switch on every backoff cycle.
					h.monitor.CancelRetry(tunnelName)
				}
				return ipc.Empty{}, err
			}
		}
	}

	if tunnelName != "" {
		// Clear BEFORE tearing down the manager-side tunnel (not after): if
		// this disconnect races with a concurrent engine-death teardown for
		// the same tunnel (tunnel.Manager's handleEngineDied, triggered by
		// wireguard-go silently self-destructing — see Engine.Died),
		// clearing the auto-reconnect gate first guarantees
		// onWireGuardEngineDied's NotifyTunnelDied call can never reconnect
		// a tunnel the user is actively disconnecting, regardless of which
		// goroutine's cleanup happens to win the race.
		h.mu.Lock()
		delete(h.activeCfgs, tunnelName)
		delete(h.autoReconnect, tunnelName)
		h.mu.Unlock()
		err := h.manager.DisconnectTunnel(tunnelName)
		// Refresh regardless of err: DisconnectTunnel can legitimately
		// report ErrNotConnected/ErrTimeout if the engine-death path
		// already tore this tunnel down concurrently — it's gone either
		// way, and the kill-switch ruleset needs to reflect that.
		h.refreshKillSwitchIfEnabled("wg-disconnect", tunnelName)
		if h.monitor != nil {
			// Cancel again in case a retry was triggered in the narrow
			// window between the CancelRetry above and the autoReconnect
			// clear just now.
			h.monitor.CancelRetry(tunnelName)
		}
		if err != nil && h.manager.IsTunnelConnected(tunnelName) {
			// Only surface the error if the tunnel is actually still there —
			// a concurrent engine-death teardown winning this exact race can
			// make DisconnectTunnel report ErrNotConnected/ErrTimeout for a
			// tunnel that is, from the user's point of view, already gone
			// exactly as they asked. Confusing to show as a failure.
			return nil, err
		}
	} else {
		// No name specified — disconnect first active OpenVPN tunnel if there
		// is no WireGuard tunnel active, then fall through to WireGuard.
		// MiniMode's Disconnect() call lands here.
		if h.ovpnManager != nil && !h.manager.IsConnected() {
			if ovpnNames := h.ovpnManager.ActiveTunnelNames(); len(ovpnNames) > 0 {
				return ipc.Empty{}, h.ovpnManager.Disconnect(ovpnNames[0])
			}
		}
		// Disconnect first WireGuard tunnel (backward compat). Same
		// clear-before-teardown reasoning as the named-tunnel branch above.
		activeName := h.manager.ActiveTunnel()
		if activeName != "" {
			h.mu.Lock()
			delete(h.activeCfgs, activeName)
			delete(h.autoReconnect, activeName)
			h.mu.Unlock()
		}
		err := h.manager.Disconnect()
		h.refreshKillSwitchIfEnabled("wg-disconnect", activeName)
		if h.monitor != nil && activeName != "" {
			h.monitor.CancelRetry(activeName)
		}
		if err != nil {
			return nil, err
		}
	}
	return ipc.Empty{}, nil
}

func (h *Helper) handleStatus(params json.RawMessage) (interface{}, error) {
	return h.statusDTO(), nil
}

func (h *Helper) handleIsConnected(params json.RawMessage) (interface{}, error) {
	return ipc.BoolResponse{Value: h.manager.IsConnected()}, nil
}

func (h *Helper) handleActiveName(params json.RawMessage) (interface{}, error) {
	name := h.manager.ActiveTunnel()
	// Fall back to the first active OpenVPN tunnel when no WireGuard tunnel is up.
	if name == "" && h.ovpnManager != nil {
		if ovpnNames := h.ovpnManager.ActiveTunnelNames(); len(ovpnNames) > 0 {
			name = ovpnNames[0]
		}
	}
	return ipc.StringResponse{Value: name}, nil
}

func (h *Helper) handleActiveTunnels(params json.RawMessage) (interface{}, error) {
	names := h.manager.ActiveTunnels()
	if h.ovpnManager != nil {
		for _, n := range h.ovpnManager.ActiveTunnelNames() {
			names = append(names, n)
		}
	}
	return ipc.ActiveTunnelsResponse{Names: names}, nil
}

func (h *Helper) handleSetKillSwitch(params json.RawMessage) (interface{}, error) {
	var req ipc.KillSwitchRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	// A manual toggle is authoritative — it must win over any stale
	// suspend/resume bookkeeping left behind by a cancelled or abandoned
	// reconnect retry sequence (see clearFirewallSuspendState).
	h.clearFirewallSuspendState()
	if req.Enabled {
		if err := h.enableKillSwitchNow(); err != nil {
			return nil, err
		}
	} else {
		if err := h.firewall.DisableKillSwitch(); err != nil {
			return nil, err
		}
	}
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetDNSProtection(params json.RawMessage) (interface{}, error) {
	var req ipc.DNSProtectionRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	// See handleSetKillSwitch — same rationale.
	h.clearFirewallSuspendState()
	if req.Enabled {
		// DNS protection uses a single tunnel's interface name for the pf
		// rule. This is intentional: the pf rule blocks port 53 globally
		// and only allows it through the tunnel interface. With multiple
		// tunnels, using the first connected tunnel's interface is
		// sufficient because the DNS protection rule is a global "block
		// port 53 except on <tunnel_iface>" anchor — any tunnel interface
		// will work as the exception — which is also why it's fine to
		// prefer WireGuard's interface when both protocols are active and
		// fall back to the first active OpenVPN tunnel's when WireGuard
		// isn't connected, rather than needing to pick "the right" one.
		ifaceName := ""
		if status := h.manager.Status(); status.State == tunnel.StateConnected {
			ifaceName = status.InterfaceName
		} else if h.ovpnManager != nil {
			for _, ovpnStatus := range h.ovpnManager.AllStatuses() {
				if ovpnStatus.State == domain.StateConnected && ovpnStatus.InterfaceName != "" {
					ifaceName = ovpnStatus.InterfaceName
					break
				}
			}
		}
		if ifaceName == "" {
			return nil, fmt.Errorf("no active tunnel")
		}
		if err := h.firewall.EnableDNSProtection(ifaceName, req.DNSServers); err != nil {
			return nil, err
		}
	} else {
		if err := h.firewall.DisableDNSProtection(); err != nil {
			return nil, err
		}
	}
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetHealthCheck(params json.RawMessage) (interface{}, error) {
	var req ipc.SetHealthCheckRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if h.monitor != nil {
		h.monitor.SetHealthCheck(req.Enabled)
	}
	return ipc.Empty{}, nil
}

func (h *Helper) handleSetPinInterface(params json.RawMessage) (interface{}, error) {
	var req ipc.SetPinInterfaceRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	h.manager.SetPinInterface(req.Enabled)
	return ipc.Empty{}, nil
}

// connectOpenVPN brings up an OpenVPN tunnel. Called from handleConnect (which
// already holds connectMu) when the request protocol is OpenVPN. The raw .ovpn
// content is validated server-side and handed to the OpenVPN manager.
func (h *Helper) connectOpenVPN(req *ipc.ConnectRequest) (interface{}, error) {
	if h.ovpnManager == nil {
		return nil, fmt.Errorf("openvpn support not available")
	}
	if req.TunnelName == "" {
		return nil, fmt.Errorf("tunnel_name is required for OpenVPN")
	}
	// The name is interpolated directly into runtime file paths in
	// ovpn.Manager (configPath/sockPath/logPath) with no sanitization of
	// its own — reject anything ValidateTunnelName wouldn't accept as a
	// saved tunnel's name before it ever reaches that code, or a name like
	// "../../../etc/foo" lets a caller make this root process write an
	// attacker-controlled file outside its runtime dir.
	if err := storage.ValidateTunnelName(req.TunnelName); err != nil {
		return nil, fmt.Errorf("invalid tunnel name: %w", err)
	}
	if req.OVPNConfig == "" {
		return nil, fmt.Errorf("ovpn_config is required for OpenVPN")
	}
	// Re-validate server-side (don't trust client).
	if err := ovpn.ValidateOVPN([]byte(req.OVPNConfig)); err != nil {
		return nil, fmt.Errorf("invalid openvpn config: %w", err)
	}

	// Already active? Treat as a no-op via the typed code (matches WireGuard).
	for _, n := range h.ovpnManager.ActiveTunnelNames() {
		if n == req.TunnelName {
			return nil, &ipc.CodedError{
				Code:    ipc.ErrCodeAlreadyConnected,
				Message: fmt.Sprintf("tunnel %q is already connected", req.TunnelName),
			}
		}
	}

	// Cache the raw config + auto-reconnect preference BEFORE dispatching,
	// mirroring handleConnect's WireGuard path — the reconnect monitor's
	// NotifyTunnelDied (wired to ovpn.Manager.SetOnDied) needs both to
	// recover this tunnel if it later dies unexpectedly. Without this, the
	// OpenVPN "auto-reconnect" toggle was silently a no-op: nothing ever
	// recorded the preference, so shouldReconnectFn always saw false.
	h.mu.Lock()
	h.activeOVPNCfgs[req.TunnelName] = []byte(req.OVPNConfig)
	h.autoReconnect[req.TunnelName] = req.AutoReconnect
	h.mu.Unlock()

	if err := h.ovpnManager.Connect(req.TunnelName, []byte(req.OVPNConfig)); err != nil {
		h.mu.Lock()
		delete(h.activeOVPNCfgs, req.TunnelName)
		delete(h.autoReconnect, req.TunnelName)
		h.mu.Unlock()
		return nil, err
	}
	return ipc.Empty{}, nil
}

// handleFeedCredentials delivers credentials to an OpenVPN tunnel that is
// blocked on an auth prompt. FullPassword = basePassword + TOTP code, combined
// by the GUI.
func (h *Helper) handleFeedCredentials(params json.RawMessage) (interface{}, error) {
	var req ipc.FeedCredentialsRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if h.ovpnManager == nil {
		return nil, fmt.Errorf("openvpn support not available")
	}
	if err := h.ovpnManager.FeedCredentials(req.TunnelName, req.Username, req.FullPassword, req.Response); err != nil {
		return nil, err
	}
	return ipc.Empty{}, nil
}
