// Package firewall provides the pf kill switch and DNS leak protection.
package firewall

// KillSwitchTunnel is one tunnel the ruleset must let through: traffic on
// its interface, plus the transport to its server endpoint(s) on any
// interface. InterfaceName is empty for a tunnel that is reconnecting (its
// utun is gone), in which case only the endpoints are passed.
type KillSwitchTunnel struct {
	InterfaceName string
	Proto         string   // "udp" or "tcp"; empty defaults to "udp"
	Endpoints     []string // literal "ip:port" or bare "ip"
}

// Ruleset is the complete desired pf state. Every Apply rebuilds the whole
// anchor from it; there is no incremental add/remove.
type Ruleset struct {
	// KillSwitch blocks everything except loopback, DHCP, IPv6 neighbour
	// discovery, the tunnels' interfaces and their endpoints. With no
	// Tunnels it blocks everything else (a dead tunnel kept fail-closed).
	KillSwitch bool
	Tunnels    []KillSwitchTunnel

	// DNSProtection blocks port 53 except to DNSServers via a tunnel
	// interface. Pending (no rules) while DNSServers is empty, unless a
	// tunnel is reconnecting: then all DNS is blocked except
	// DNSLookupServers.
	DNSProtection bool
	DNSServers    []string

	// DNSLookupServers passes port 53 to these resolvers (the system's own,
	// on any interface). Set only for the moment a reconnecting tunnel
	// re-resolves its hostname endpoints; never "port 53 to any".
	DNSLookupServers []string
}

// FirewallManager loads a Ruleset into pf.
type FirewallManager interface {
	// Apply replaces the loaded rules with rs. A ruleset that enforces
	// nothing removes our rules and restores pf's original enabled state.
	// On error the previously loaded rules stay in place (fail closed).
	Apply(rs Ruleset) error

	// Cleanup removes all rules (helper shutdown).
	Cleanup() error
}
