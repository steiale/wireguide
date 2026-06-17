package app

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/ovpn"
	"github.com/steiale/wireguide/internal/storage"
	"github.com/steiale/wireguide/internal/tunnel"
)

// ListTunnelsLocal returns stored tunnels WITHOUT asking the helper which one
// is active — callers that already know the active name (e.g. the system
// tray, which tracks it from the status event stream) should use this to
// avoid an IPC round-trip on every refresh. IsConnected is always false in
// the returned slice; the caller is responsible for applying its own
// active-name match.
func (s *TunnelService) ListTunnelsLocal() ([]TunnelInfo, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}
	var result []TunnelInfo
	for _, name := range names {
		info, ok := s.tunnelInfoFor(name, "")
		if !ok {
			continue
		}
		result = append(result, info)
	}
	return result, nil
}

// tunnelInfoFor builds a TunnelInfo for one stored tunnel, dispatching on
// protocol. activeName, when non-empty, marks IsConnected on a name match. The
// bool return is false when the tunnel could not be loaded (skip it).
func (s *TunnelService) tunnelInfoFor(name, activeName string) (TunnelInfo, bool) {
	// M6: Surface real LoadMeta errors at warn level instead of dropping them
	// silently. A missing meta file is normal and returns nil err from LoadMeta.
	meta, err := s.tunnelStore.LoadMeta(name)
	if err != nil {
		slog.Warn("loading tunnel meta failed; treating as empty", "name", name, "error", err)
	}
	notes := ""
	protocol := domain.ProtocolWireGuard
	if meta != nil {
		notes = meta.Notes
		protocol = domain.NormalizeProtocol(meta.Protocol)
	}

	endpoint := ""
	if protocol == domain.ProtocolOpenVPN {
		if content, err := s.tunnelStore.LoadOVPN(name); err != nil {
			slog.Warn("skipping broken openvpn tunnel", "name", name, "error", err)
			return TunnelInfo{}, false
		} else if cfg, perr := ovpn.ParseOVPN([]byte(content)); perr == nil {
			endpoint = cfg.Remote
		}
	} else {
		cfg, err := s.tunnelStore.Load(name)
		if err != nil {
			slog.Warn("skipping broken tunnel config", "name", name, "error", err)
			return TunnelInfo{}, false
		}
		if len(cfg.Peers) > 0 {
			endpoint = cfg.Peers[0].Endpoint
		}
	}

	return TunnelInfo{
		Name:        name,
		IsConnected: activeName != "" && name == activeName,
		Endpoint:    endpoint,
		Notes:       notes,
		Protocol:    protocol,
	}, true
}

// ListTunnels returns every stored tunnel with its summary info.
//
// The active-tunnel marker used to come from an IPC round-trip on every call.
// That made the tray's rebuild-menu path slow when it was being invoked on
// the status event stream. The frontend now learns the active tunnel from
// the status event itself, and the tray caches it internally — so this
// function stays fully local (disk-only, no IPC) and returns IsConnected
// purely as a best-effort flag based on a single active-name probe that is
// safe to skip entirely on slow paths.
func (s *TunnelService) ListTunnels() ([]TunnelInfo, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}

	// One cheap probe for the active tunnel — used by the frontend's initial
	// load before it has received its first status event. The tray no longer
	// relies on this (it tracks active tunnel via the status stream).
	var active ipc.StringResponse
	_ = s.call(ipc.MethodActiveName, nil, &active)

	var result []TunnelInfo
	for _, name := range names {
		info, ok := s.tunnelInfoFor(name, active.Value)
		if !ok {
			continue
		}
		result = append(result, info)
	}
	return result, nil
}

// CheckConflicts loads a tunnel's config and scans local network interfaces
// for routing overlaps (e.g. Tailscale, another WireGuard instance). Runs
// entirely in the GUI process — no IPC needed. The frontend calls this before
// Connect so it can show a warning dialog if conflicts exist.
func (s *TunnelService) CheckConflicts(name string) ([]tunnel.ConflictInfo, error) {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return nil, fmt.Errorf("loading tunnel %s: %w", name, err)
	}
	var allowedIPs []string
	for _, peer := range cfg.Peers {
		allowedIPs = append(allowedIPs, peer.AllowedIPs...)
	}
	conflicts, err := tunnel.CheckConflicts(allowedIPs)
	if err != nil {
		slog.Warn("conflict check failed", "tunnel", name, "error", err)
		// Non-fatal — don't block connect if the scan itself fails.
		return nil, nil
	}
	return conflicts, nil
}

// Connect loads a tunnel config from local storage and asks the helper to
// bring it up. The helper re-validates server-side. OpenVPN tunnels are routed
// to the OpenVPN connect path.
func (s *TunnelService) Connect(name string) error {
	// Read per-tunnel auto-reconnect + protocol preference.
	meta, _ := s.tunnelStore.LoadMeta(name)
	autoReconnect := meta != nil && meta.AutoReconnect
	protocol := domain.ProtocolWireGuard
	if meta != nil {
		protocol = domain.NormalizeProtocol(meta.Protocol)
	}

	// OpenVPN: send the raw .ovpn content to the helper. Credentials (and any
	// TOTP code) are handled asynchronously via the auth-prompt event.
	if protocol == domain.ProtocolOpenVPN {
		content, err := s.tunnelStore.LoadOVPN(name)
		if err != nil {
			return fmt.Errorf("loading openvpn tunnel %s: %w", name, err)
		}
		s.clients.MarkInflight()
		defer s.clients.UnmarkInflight()
		if err := s.callLong(ipc.MethodConnect, ipc.ConnectRequest{
			Protocol:      domain.ProtocolOpenVPN,
			TunnelName:    name,
			OVPNConfig:    content,
			AutoReconnect: autoReconnect,
		}, nil); err != nil {
			return err
		}
		s.recordConnectStart(name)
		return nil
	}

	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return fmt.Errorf("loading tunnel %s: %w", name, err)
	}

	// Mark the RPC as in-flight so the health monitor doesn't falsely
	// detect helper death while the server is busy processing Connect
	// (which blocks the per-connection request loop, preventing pings).
	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()

	if err := s.callLong(ipc.MethodConnect, ipc.ConnectRequest{
		Config:        cfg,
		AutoReconnect: autoReconnect,
	}, nil); err != nil {
		return err
	}

	// Record the session AFTER the helper accepted the connect. If the user
	// quickly reconnects the same tunnel (rare), close the old open session
	// with reason "reconnect" before opening a new one — leaving an
	// indefinitely open row would lie to the user.
	s.recordConnectStart(name)
	return nil
}

// Disconnect tears down whatever tunnel the helper currently has active.
// If the call fails with a "client closed" error (the health monitor may have
// swapped the client during a recovery), retry once with the fresh client.
func (s *TunnelService) Disconnect() error {
	// Snapshot rx/tx + name BEFORE the IPC tear-down — once disconnected the
	// helper drops the per-tunnel counters and we lose the totals forever.
	name, rx, tx := s.snapshotActiveStats("")

	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()
	err := s.callLong(ipc.MethodDisconnect, nil, nil)
	if err != nil && isClientClosed(err) {
		slog.Info("disconnect got client-closed, retrying with fresh client")
		err = s.callLong(ipc.MethodDisconnect, nil, nil)
	}
	if err == nil {
		s.recordDisconnectEnd(name, rx, tx, "user")
	}
	return err
}

// SaveCredentials stores OpenVPN credentials (username + base password) in the
// helper-side Keychain. The TOTP code is never stored — only the static base
// password the user enters once.
func (s *TunnelService) SaveCredentials(tunnelName, username, basePassword string) error {
	return s.call(ipc.MethodSaveCredentials, ipc.SaveCredentialsRequest{
		TunnelName:   tunnelName,
		Username:     username,
		BasePassword: basePassword,
	}, nil)
}

// SavedCredentials holds the stored username + base password for an OpenVPN
// tunnel. Returned by GetSavedCredentials so the auth modal can pre-fill fields.
type SavedCredentials struct {
	Username     string `json:"username"`
	BasePassword string `json:"base_password"`
}

// GetSavedCredentials loads the cached OpenVPN credentials for tunnelName from
// the Keychain (if any). Returns nil without error when nothing is stored — the
// caller should treat a nil result as "no saved creds, show empty fields".
func (s *TunnelService) GetSavedCredentials(tunnelName string) (*SavedCredentials, error) {
	creds, err := ovpn.LoadCredentials(tunnelName)
	if err != nil {
		// "could not be found" is not an error condition for the modal.
		return nil, nil //nolint:nilerr
	}
	return &SavedCredentials{
		Username:     creds.Username,
		BasePassword: creds.BasePassword,
	}, nil
}

// FeedCredentials delivers credentials to an OpenVPN tunnel waiting on an auth
// prompt. fullPassword must already be basePassword + the 6-digit TOTP code,
// combined by the caller (the GUI prompts for the code on every connect).
func (s *TunnelService) FeedCredentials(tunnelName, username, fullPassword string) error {
	return s.call(ipc.MethodFeedCredentials, ipc.FeedCredentialsRequest{
		TunnelName:   tunnelName,
		Username:     username,
		FullPassword: fullPassword,
	}, nil)
}

// DisconnectTunnel disconnects a specific tunnel by name.
func (s *TunnelService) DisconnectTunnel(name string) error {
	_, rx, tx := s.snapshotActiveStats(name)

	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()
	err := s.callLong(ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: name}, nil)
	if err == nil {
		s.recordDisconnectEnd(name, rx, tx, "user")
	}
	return err
}

// recordConnectStart opens a new history session for name. If the same tunnel
// already has an open session (e.g. helper-side reconnect), close it as a
// "reconnect" first so the timeline stays honest.
func (s *TunnelService) recordConnectStart(name string) {
	if s.history == nil || name == "" {
		return
	}
	if prev, loaded := s.activeSessions.LoadAndDelete(name); loaded {
		if id, ok := prev.(string); ok && id != "" {
			s.history.RecordDisconnect(id, 0, 0, "reconnect")
		}
	}
	id := s.history.RecordConnect(name)
	s.activeSessions.Store(name, id)
}

// recordDisconnectEnd closes the open session for name. Pulls the session ID
// from the activeSessions map; no-op if there isn't one (e.g. the helper was
// already disconnected when the GUI started).
func (s *TunnelService) recordDisconnectEnd(name string, rx, tx int64, reason string) {
	if s.history == nil {
		return
	}
	if name == "" {
		// Disconnect() with no tunnel name. Best-effort: close every open
		// session — there's almost always exactly one.
		s.activeSessions.Range(func(k, v interface{}) bool {
			if id, ok := v.(string); ok && id != "" {
				s.history.RecordDisconnect(id, rx, tx, reason)
			}
			s.activeSessions.Delete(k)
			return true
		})
		return
	}
	v, ok := s.activeSessions.LoadAndDelete(name)
	if !ok {
		return
	}
	id, ok := v.(string)
	if !ok || id == "" {
		return
	}
	s.history.RecordDisconnect(id, rx, tx, reason)
}

// snapshotActiveStats returns (tunnelName, rx, tx) for the tunnel about to
// disconnect. If wantName is "" the primary active tunnel is used. Returns
// zero values on any error — capturing stats is best-effort and never blocks
// disconnect.
func (s *TunnelService) snapshotActiveStats(wantName string) (string, int64, int64) {
	status, err := s.GetStatus()
	if err != nil || status == nil {
		return wantName, 0, 0
	}
	if wantName == "" {
		// Find primary: first prefer status.TunnelName, then status.Tunnels.
		if status.TunnelName != "" {
			return status.TunnelName, status.RxBytes, status.TxBytes
		}
		if len(status.Tunnels) > 0 {
			t := status.Tunnels[0]
			return t.TunnelName, t.RxBytes, t.TxBytes
		}
		return "", 0, 0
	}
	if status.TunnelName == wantName {
		return wantName, status.RxBytes, status.TxBytes
	}
	for _, t := range status.Tunnels {
		if t.TunnelName == wantName {
			return wantName, t.RxBytes, t.TxBytes
		}
	}
	return wantName, 0, 0
}

// ReconcileHistoryFromStatus syncs the history's open-session map against the
// list of active tunnels reported by the helper. Used by the event bridge so
// helper-driven Connect / Disconnect (auto-reconnect on wake, health-check
// recovery, etc.) is recorded too — not just the buttons in the GUI.
//
// reason classifies sessions that disappeared since the last call:
//   - "" : default — store as "reconnect"
//   - "health_check" : helper detected a stale handshake and is re-bringing it up
//
// rxByTunnel/txByTunnel let the caller forward last-known counters from the
// status event itself; missing keys default to 0.
func (s *TunnelService) ReconcileHistoryFromStatus(activeNames []string, rxByTunnel, txByTunnel map[string]int64, disappearReason string) {
	if s.history == nil {
		return
	}
	if disappearReason == "" {
		disappearReason = "reconnect"
	}
	active := make(map[string]struct{}, len(activeNames))
	for _, n := range activeNames {
		if n != "" {
			active[n] = struct{}{}
		}
	}

	// Close sessions for tunnels that are no longer active.
	s.activeSessions.Range(func(k, v interface{}) bool {
		name, _ := k.(string)
		id, _ := v.(string)
		if _, stillActive := active[name]; stillActive {
			return true
		}
		if id != "" {
			rx := int64(0)
			tx := int64(0)
			if rxByTunnel != nil {
				rx = rxByTunnel[name]
			}
			if txByTunnel != nil {
				tx = txByTunnel[name]
			}
			s.history.RecordDisconnect(id, rx, tx, disappearReason)
		}
		s.activeSessions.Delete(k)
		return true
	})

	// Open sessions for active tunnels we don't have yet (helper-side
	// connect that didn't go through TunnelService.Connect).
	for _, name := range activeNames {
		if name == "" {
			continue
		}
		if _, exists := s.activeSessions.Load(name); exists {
			continue
		}
		id := s.history.RecordConnect(name)
		s.activeSessions.Store(name, id)
	}
}

// CloseHistorySessions closes any open history sessions with reason. Called
// from gui.Run during shutdown so the UI doesn't show phantom "Active" rows
// after a quit.
func (s *TunnelService) CloseHistorySessions(reason string) {
	if s.history == nil {
		return
	}
	// Try to attach last-known rx/tx for each open session before closing.
	s.activeSessions.Range(func(k, v interface{}) bool {
		name, _ := k.(string)
		id, _ := v.(string)
		if id == "" {
			return true
		}
		_, rx, tx := s.snapshotActiveStats(name)
		s.history.RecordDisconnect(id, rx, tx, reason)
		s.activeSessions.Delete(k)
		return true
	})
	// Anything still open in the file (e.g. from a previous crash) gets
	// closed too.
	s.history.CloseOpenSessions(reason)
}

// isClientClosed returns true for errors caused by the IPC client being closed
// mid-call (e.g., health monitor swapped clients during recovery).
// L1: Match the sentinel error from ipc.ErrClientClosed via errors.Is rather
// than substring-matching the error message, which is fragile and silently
// breaks the moment the wording changes.
func isClientClosed(err error) bool {
	return errors.Is(err, ipc.ErrClientClosed)
}

// IsHelperReady reports whether the helper IPC client is connected.
// Used by the frontend on mount to avoid relying on events that may have
// fired before the listener was registered.
func (s *TunnelService) IsHelperReady() bool {
	return s.clients.Get() != nil
}

// GetStatus queries the helper for the current connection status. IPC errors
// are surfaced to the caller — the frontend needs to distinguish "helper says
// disconnected" from "helper unreachable".
func (s *TunnelService) GetStatus() (*ConnectionStatus, error) {
	var status ConnectionStatus
	if err := s.call(ipc.MethodStatus, nil, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// GetTunnelDetail returns the full WireGuardConfig for a tunnel. Used by the
// detail pane to show allowed IPs, DNS, public keys, etc.
func (s *TunnelService) GetTunnelDetail(name string) (*domain.WireGuardConfig, error) {
	return s.tunnelStore.Load(name)
}

// DeleteTunnel removes a tunnel from local storage. Rejects deletion of the
// currently connected tunnel (would orphan the interface).
func (s *TunnelService) DeleteTunnel(name string) error {
	var active ipc.StringResponse
	if err := s.call(ipc.MethodActiveName, nil, &active); err != nil {
		return fmt.Errorf("cannot verify tunnel state (helper unreachable): %w", err)
	}
	if active.Value == name {
		return fmt.Errorf("cannot delete connected tunnel %q — disconnect first", name)
	}
	// Best-effort: remove any stored OpenVPN credentials for this tunnel. Done
	// directly (not via IPC) since Keychain access works from the GUI process
	// and a missing item is treated as success.
	if s.tunnelStore.IsOVPN(name) {
		if err := ovpn.DeleteCredentials(name); err != nil {
			slog.Warn("failed to delete openvpn credentials", "name", name, "error", err)
		}
	}
	return s.tunnelStore.Delete(name)
}

// RenameTunnel changes a tunnel's name. Rejects rename of the connected
// tunnel since the interface name is derived from it.
func (s *TunnelService) RenameTunnel(oldName, newName string) error {
	if err := storage.ValidateTunnelName(newName); err != nil {
		return err
	}
	var active ipc.StringResponse
	if err := s.call(ipc.MethodActiveName, nil, &active); err != nil {
		return fmt.Errorf("cannot verify tunnel state (helper unreachable): %w", err)
	}
	if active.Value == oldName {
		return fmt.Errorf("cannot rename connected tunnel %q — disconnect first", oldName)
	}
	return s.tunnelStore.Rename(oldName, newName)
}

// TunnelExists reports whether a tunnel with the given name is stored.
func (s *TunnelService) TunnelExists(name string) bool {
	return s.tunnelStore.Exists(name)
}
