package app

import (
	"net"
	"strings"

	"github.com/steiale/wireguide/internal/diag"
	"github.com/steiale/wireguide/internal/ipc"
)

// DNSLeakResult mirrors diag.DNSLeakResult for Wails JSON serialisation.
type DNSLeakResult struct {
	Leaked     bool        `json:"leaked"`
	DNSServers []DNSServer `json:"dns_servers"`
	TestDomain string      `json:"test_domain"`
	Error      string      `json:"error,omitempty"`
}

// DNSServer mirrors diag.DNSServer.
type DNSServer struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	IsVPN    bool   `json:"is_vpn"`
}

// RouteEntry mirrors diag.RouteEntry for Wails JSON serialisation.
type RouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Flags       string `json:"flags"`
}

// RunDNSLeakTest performs a DNS leak test using the currently active tunnel's
// DNS servers as the expected (VPN) resolvers. If no tunnel is connected, the
// expected set is empty — all detected resolvers will be flagged as leaks.
func (s *TunnelService) RunDNSLeakTest() (*DNSLeakResult, error) {
	// Best-effort: find the active tunnel's DNS config to know which resolvers
	// are expected to be in use. Ignore IPC errors — an empty expected set is
	// still a valid (conservative) test.
	var expectedDNS []string
	if status, err := s.GetStatus(); err == nil && status != nil && status.TunnelName != "" {
		if cfg, err := s.tunnelStore.Load(status.TunnelName); err == nil && cfg != nil {
			expectedDNS = cfg.Interface.DNS
		}
	}

	r := diag.RunDNSLeakTest(expectedDNS)
	out := &DNSLeakResult{
		Leaked:     r.Leaked,
		TestDomain: r.TestDomain,
		Error:      r.Error,
	}
	for _, srv := range r.DNSServers {
		out.DNSServers = append(out.DNSServers, DNSServer{
			IP:       srv.IP,
			Hostname: srv.Hostname,
			IsVPN:    srv.IsVPN,
		})
	}
	return out, nil
}

// GetTunnelLatency returns round-trip latency in ms for the named tunnel.
//
// When connected: pings the tunnel's DNS servers (inner VPN gateway) — avoids
// the full-tunnel loop where pinging the public endpoint routes back through
// the tunnel itself and never gets a reply.
//
// When disconnected: pings the public endpoint directly, which gives a useful
// pre-connection latency estimate even without an active tunnel.
//
// Returns -1 if unreachable.
func (s *TunnelService) GetTunnelLatency(name string) int {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return -1
	}

	// Check whether this tunnel is currently active.
	var active ipc.StringResponse
	connected := s.call(ipc.MethodActiveName, nil, &active) == nil && active.Value == name

	if connected {
		// Ping each DNS server IP (skip search domains).
		for _, entry := range cfg.Interface.DNS {
			entry = strings.TrimSpace(entry)
			if net.ParseIP(entry) == nil {
				continue
			}
			if r := diag.PingEndpoint(entry); r.Reachable {
				return int(r.LatencyMs)
			}
		}
	}

	// Disconnected (or no DNS configured): ping the public endpoint.
	if len(cfg.Peers) > 0 && cfg.Peers[0].Endpoint != "" {
		if r := diag.PingEndpoint(cfg.Peers[0].Endpoint); r.Reachable {
			return int(r.LatencyMs)
		}
	}

	return -1
}

// GetRoutingTable returns the current OS routing table.
func (s *TunnelService) GetRoutingTable() ([]RouteEntry, error) {
	entries, err := diag.GetRoutingTable()
	if err != nil {
		return nil, err
	}
	out := make([]RouteEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, RouteEntry{
			Destination: e.Destination,
			Gateway:     e.Gateway,
			Interface:   e.Interface,
			Flags:       e.Flags,
		})
	}
	return out, nil
}
