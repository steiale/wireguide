// Package network provides macOS IP, routing, and DNS configuration.
package network

// NetworkManager handles OS-level network configuration for a tunnel.
type NetworkManager interface {
	// AssignAddress assigns IP addresses (CIDR) to the interface.
	AssignAddress(ifaceName string, addresses []string) error

	// SetMTU sets the interface MTU; 0 auto-detects (upstream MTU - 80).
	SetMTU(ifaceName string, mtu int) error

	// BringUp brings the interface up.
	BringUp(ifaceName string) error

	// AddRoutes adds routes for allowedIPs via the interface, using the
	// split-route trick plus endpoint bypass routes for a full tunnel.
	// endpointIPs must be ALREADY-RESOLVED IP literals: resolving here would
	// send the query through the half-installed tunnel. tableCfg "off" skips
	// route installation (wg-quick's Table = off).
	AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpointIPs []string, tableCfg string) error

	// SetDNS registers this holder's DNS entries (servers and search
	// domains); the system gets the union of all holders.
	SetDNS(holder string, entries []string) error

	// RestoreDNS releases holder's DNS entries; the original settings come
	// back once no holder remains.
	RestoreDNS(holder string) error

	// Cleanup removes the interface's routes and bypass routes, stops the
	// route monitor and releases its DNS hold.
	Cleanup(ifaceName string) error
}
