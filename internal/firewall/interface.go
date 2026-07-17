// Package firewall provides OS-specific kill switch and DNS leak protection.
package firewall

// KillSwitchTunnel describes one additional active tunnel — beyond the
// "primary" WireGuard interfaceName/endpoints params of EnableKillSwitch —
// that kill switch rules must also allow traffic for. Used for OpenVPN
// tunnels active alongside (or instead of) WireGuard: unlike WireGuard
// (always UDP, one endpoint per peer), OpenVPN commonly runs over TCP and
// its remote/protocol come from the .ovpn config rather than a fixed scheme,
// so each one needs its own interface + protocol + endpoint tuple.
type KillSwitchTunnel struct {
	InterfaceName string
	Proto         string   // "udp" or "tcp"; empty defaults to "udp"
	Endpoints     []string // "ip:port" or bare "ip" entries (remote server)
}

// FirewallManager controls kill switch and DNS leak protection.
type FirewallManager interface {
	// EnableKillSwitch blocks all traffic except through the active tunnel(s).
	// interfaceName: WG interface (e.g., "utun4"), or "" if no WireGuard
	//   tunnel is active — in that case extra must be non-empty.
	// ifaceAddresses: WG interface addresses (CIDR, e.g. "10.0.0.2/24") — used on
	//   Linux to build anti-spoof (preraw) nftables chains.
	// endpoints: pre-resolved WG server endpoints as "ip:port" pairs — must be
	//   allowed through. Callers must resolve hostnames BEFORE the tunnel routes
	//   are installed, otherwise DNS resolution would go through the tunnel and
	//   may fail. If port is unknown or not applicable, use "ip:" (empty port).
	// extra: additional (typically OpenVPN) tunnels to also whitelist —
	//   see KillSwitchTunnel. May be empty.
	EnableKillSwitch(interfaceName string, ifaceAddresses []string, endpoints []string, extra []KillSwitchTunnel) error

	// DisableKillSwitch removes all kill switch firewall rules.
	DisableKillSwitch() error

	// EnableDNSProtection blocks DNS (port 53) except to specified servers via WG tunnel.
	EnableDNSProtection(interfaceName string, dnsServers []string) error

	// DisableDNSProtection removes DNS protection rules.
	DisableDNSProtection() error

	// IsKillSwitchEnabled returns the current kill switch state.
	IsKillSwitchEnabled() bool

	// IsDNSProtectionEnabled returns the current DNS protection state.
	IsDNSProtectionEnabled() bool

	// Cleanup removes all firewall rules (called on shutdown/crash recovery).
	Cleanup() error
}
