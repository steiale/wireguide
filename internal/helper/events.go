package helper

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/ipc"
)

// statusDTO returns the current connection status for broadcast. Since the
// tunnel package's ConnectionStatus is already an alias for the domain type
// with wire-safe JSON tags, we just dereference and return it — no field-by-
// field translation.
func (h *Helper) statusDTO() ipc.ConnectionStatus {
	s := h.manager.Status()

	// Gather OpenVPN tunnel statuses (managed separately from WireGuard).
	var ovpnStatuses []domain.ConnectionStatus
	if h.ovpnManager != nil {
		ovpnStatuses = h.ovpnManager.AllStatuses()
	}

	var result ipc.ConnectionStatus
	switch {
	case s != nil && s.State != domain.StateDisconnected:
		// WireGuard has an active tunnel — use it as primary.
		result = *s
	case len(ovpnStatuses) > 0:
		// No WireGuard tunnel — promote the first OpenVPN tunnel to primary so
		// single-OpenVPN-tunnel UIs work without consulting result.Tunnels.
		result = ovpnStatuses[0]
	default:
		return ipc.ConnectionStatus{}
	}

	// Include full per-tunnel info (rx/tx/duration included, matching the
	// OpenVPN loop below) so the frontend can render correct stats/speed
	// data for whichever tunnel's card is actually expanded — not just the
	// "primary" one. This used to omit rx/tx/duration here as a bandwidth
	// optimization ("full stats only in the primary status"), but that
	// meant expanding a second WireGuard tunnel's card (or, before OpenVPN
	// entries got full stats too, any non-primary tunnel) always showed
	// zeroed-out traffic — the exact same class of bug the OpenVPN loop
	// below doesn't have. A few extra int64 fields per tunnel per second is
	// negligible next to that correctness gap, especially since a user
	// realistically has at most a small handful of concurrent tunnels.
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
					Protocol:      domain.ProtocolWireGuard,
				})
			}
		}
	}
	// Append OpenVPN tunnels to the per-tunnel list (and to ActiveTunnels).
	for _, ts := range ovpnStatuses {
		result.Tunnels = append(result.Tunnels, domain.ConnectionStatus{
			State:         ts.State,
			TunnelName:    ts.TunnelName,
			RxBytes:       ts.RxBytes,
			TxBytes:       ts.TxBytes,
			Duration:      ts.Duration,
			LastHandshake: ts.LastHandshake,
			HasHandshake:  ts.HasHandshake,
			Protocol:      domain.ProtocolOpenVPN,
			DNSServers:    ts.DNSServers,
		})
		result.ActiveTunnels = appendUnique(result.ActiveTunnels, ts.TunnelName)
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
