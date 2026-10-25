package helper

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
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
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	var req ipc.ConnectRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}

	// An empty protocol means WireGuard.
	if domain.NormalizeProtocol(req.Protocol) == domain.ProtocolOpenVPN {
		return h.connectOpenVPN(&req)
	}

	if req.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	// The name flows into root-owned file paths: never trust the caller.
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

	// Already up: a typed no-op for the GUI, without touching the cache.
	name := req.Config.Name
	if slices.Contains(h.manager.ActiveTunnels(), name) {
		return nil, &ipc.CodedError{
			Code:    ipc.ErrCodeAlreadyConnected,
			Message: fmt.Sprintf("tunnel %q is already connected", name),
		}
	}

	// Cache config + auto-reconnect before connecting (a death callback
	// during Connect must see them); restore the previous values on failure.
	h.mu.Lock()
	prevCfg, hadCfg := h.activeCfgs[name]
	prevAuto, hadAuto := h.autoReconnect[name]
	h.activeCfgs[name] = req.Config
	h.autoReconnect[name] = req.AutoReconnect
	h.mu.Unlock()

	if err := h.manager.Connect(req.Config); err != nil {
		h.mu.Lock()
		delete(h.activeCfgs, name)
		delete(h.autoReconnect, name)
		if hadCfg {
			h.activeCfgs[name] = prevCfg
		}
		if hadAuto {
			h.autoReconnect[name] = prevAuto
		}
		h.mu.Unlock()
		return nil, err
	}
	_ = h.applyFirewall("wg-connect")
	return ipc.Empty{}, nil
}

func (h *Helper) handleDisconnect(params json.RawMessage) (interface{}, error) {
	var req ipc.DisconnectRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid disconnect request: %w", err)
	}
	name := req.TunnelName
	if name == "" {
		return nil, fmt.Errorf("tunnel_name is required")
	}

	// Holding connectMu makes a concurrent reconnectFn wait, then see the
	// cleared auto-reconnect flag and give up instead of resurrecting the
	// tunnel. Cleared before teardown so a death callback racing this
	// disconnect can't schedule a reconnect either.
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	if h.monitor != nil {
		h.monitor.CancelRetry(name)
	}
	h.mu.Lock()
	delete(h.activeCfgs, name)
	delete(h.activeOVPNCfgs, name)
	delete(h.autoReconnect, name)
	delete(h.fwHeld, name)
	h.mu.Unlock()

	var err error
	isOVPN := h.ovpnManager != nil && slices.Contains(h.ovpnManager.ActiveTunnelNames(), name)
	if isOVPN {
		err = h.ovpnManager.Disconnect(name)
	} else {
		err = h.manager.DisconnectTunnel(name)
	}
	if h.monitor != nil {
		h.monitor.CancelRetry(name) // a retry registered by a racing death callback
	}
	_ = h.applyFirewall("disconnect")

	// A concurrent engine-death teardown can make DisconnectTunnel report
	// not-connected for a tunnel that is gone exactly as asked.
	if err != nil && (isOVPN || h.manager.IsTunnelConnected(name)) {
		return nil, err
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
		names = append(names, h.ovpnManager.ActiveTunnelNames()...)
	}
	return ipc.ActiveTunnelsResponse{Names: names}, nil
}

// handleSetKillSwitch sets the kill switch policy (see firewall.go): stored,
// applied now if a tunnel is up, and on every later tunnel transition.
func (h *Helper) handleSetKillSwitch(params json.RawMessage) (interface{}, error) {
	var req ipc.KillSwitchRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.policy.killSwitch = req.Enabled
	h.mu.Unlock()
	if err := h.applyFirewall("policy"); err != nil {
		return nil, err
	}
	return ipc.Empty{}, nil
}

// handleSetDNSProtection sets the DNS protection policy. The allowed
// servers are derived from the active tunnels; req.DNSServers is ignored.
func (h *Helper) handleSetDNSProtection(params json.RawMessage) (interface{}, error) {
	var req ipc.DNSProtectionRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.policy.dnsProtection = req.Enabled
	h.mu.Unlock()
	if err := h.applyFirewall("policy"); err != nil {
		return nil, err
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
	// The name becomes root-owned runtime file paths in ovpn.Manager.
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

	// openvpn only runs from the root-owned helper dir (see Run).
	if _, err := os.Stat(h.ovpnBinary); err != nil {
		return nil, fmt.Errorf("OpenVPN is unavailable: %s is missing — reinstall the helper (quit and relaunch LockPlus, then approve the admin prompt)", h.ovpnBinary)
	}

	if slices.Contains(h.ovpnManager.ActiveTunnelNames(), req.TunnelName) {
		return nil, &ipc.CodedError{
			Code:    ipc.ErrCodeAlreadyConnected,
			Message: fmt.Sprintf("tunnel %q is already connected", req.TunnelName),
		}
	}

	// Cached for the reconnect monitor, as on the WireGuard path. A new
	// attempt clears the previous error.
	h.mu.Lock()
	delete(h.ovpnErrors, req.TunnelName)
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
