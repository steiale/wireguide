package helper

import (
	"bytes"
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/ipc"
)

// statusDTO returns the current connection status for broadcast. Since the
// tunnel package's ConnectionStatus is already an alias for the domain type
// with wire-safe JSON tags, we just dereference and return it — no field-by-
// field translation.
//
// ActiveTunnels lists only tunnels that are actually running (WireGuard's
// own list, plus live OpenVPN entries not in an error state). An OpenVPN
// error kept after its process exited (State=error, ErrorMessage set) and
// a tunnel kept blocked by the kill switch (State=error, KillSwitchBlocked
// set; the GUI renders its localized text from that flag) appear in Tunnels
// only, so the GUI never counts them as connected.
func (h *Helper) statusDTO() ipc.ConnectionStatus {
	s := h.manager.Status()

	// Gather OpenVPN tunnel statuses (managed separately from WireGuard).
	var live []domain.ConnectionStatus
	if h.ovpnManager != nil {
		live = h.ovpnManager.AllStatuses()
	}
	extra := slices.Clone(live)
	present := func(name string) int {
		return slices.IndexFunc(extra, func(s domain.ConnectionStatus) bool { return s.TunnelName == name })
	}
	h.mu.Lock()
	// Tunnels the manager already removed after failing keep their last
	// error so the GUI can show it.
	for name, st := range h.ovpnErrors {
		if present(name) < 0 {
			extra = append(extra, st)
		}
	}
	if h.policy.killSwitch {
		for name, proto := range h.fwBlocked {
			if i := present(name); i >= 0 {
				extra[i].KillSwitchBlocked = true
				if extra[i].State != domain.StateConnected {
					extra[i].State = domain.StateError
				}
				continue
			}
			extra = append(extra, domain.ConnectionStatus{
				State:             domain.StateError,
				TunnelName:        name,
				Protocol:          proto,
				KillSwitchBlocked: true,
			})
		}
	}
	h.mu.Unlock()
	sort.SliceStable(extra, func(i, j int) bool { return extra[i].TunnelName < extra[j].TunnelName })

	var result ipc.ConnectionStatus
	switch {
	case s != nil && s.State != domain.StateDisconnected:
		// WireGuard has an active tunnel — use it as primary.
		result = *s
	case len(extra) > 0:
		// No WireGuard tunnel — promote the first other tunnel to primary so
		// single-tunnel UIs work without consulting result.Tunnels.
		result = extra[0]
		result.ActiveTunnels = nil
	default:
		return ipc.ConnectionStatus{}
	}

	// Full per-tunnel stats, so any expanded tunnel card shows real traffic.
	if allStats := h.manager.AllStatuses(); len(allStats) > 1 {
		for _, ts := range allStats {
			if ts != nil {
				result.Tunnels = append(result.Tunnels, domain.ConnectionStatus{
					State:         ts.State,
					TunnelName:    ts.TunnelName,
					RxBytes:       ts.RxBytes,
					TxBytes:       ts.TxBytes,
					Duration:      ts.Duration,
					LastHandshake: ts.LastHandshake,
					HasHandshake:  ts.HasHandshake,
					ErrorMessage:  ts.ErrorMessage,
					Protocol:      domain.ProtocolWireGuard,
				})
			}
		}
	}
	// Append the other tunnels to the per-tunnel list; only live, non-error
	// OpenVPN entries count as active.
	for _, ts := range extra {
		protocol := ts.Protocol
		if protocol == "" {
			protocol = domain.ProtocolOpenVPN
		}
		result.Tunnels = append(result.Tunnels, domain.ConnectionStatus{
			State:             ts.State,
			TunnelName:        ts.TunnelName,
			RxBytes:           ts.RxBytes,
			TxBytes:           ts.TxBytes,
			Duration:          ts.Duration,
			LastHandshake:     ts.LastHandshake,
			HasHandshake:      ts.HasHandshake,
			ErrorMessage:      ts.ErrorMessage,
			Protocol:          protocol,
			DNSServers:        ts.DNSServers,
			KillSwitchBlocked: ts.KillSwitchBlocked,
		})
		isLive := slices.ContainsFunc(live, func(l domain.ConnectionStatus) bool { return l.TunnelName == ts.TunnelName })
		if isLive && ts.State != domain.StateError {
			result.ActiveTunnels = appendUnique(result.ActiveTunnels, ts.TunnelName)
		}
	}
	return result
}

// appendUnique appends name to names only if not already present.
func appendUnique(names []string, name string) []string {
	for _, n := range names {
		if n == name {
			return names
		}
	}
	return append(names, name)
}

// eventLoop broadcasts status updates to subscribed GUIs on change. Change
// detection is done by JSON round-trip compare (robust against field swaps).
func (h *Helper) eventLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastJSON []byte
	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			h.rearmShutdownIfIdle()
			h.checkOVPNWatchdog(time.Now())
			status := h.statusDTO()
			currentJSON, err := json.Marshal(status)
			if err != nil {
				continue
			}
			if !bytes.Equal(lastJSON, currentJSON) {
				lastJSON = currentJSON
				h.server.Broadcast(ipc.EventStatus, status)
			}
		}
	}
}
