package firewall

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// validIfaceName matches macOS interface names like utun4, en0, lo0.
var validIfaceName = regexp.MustCompile(`^[a-z]+[0-9]+$`)

// validatePort rejects anything but a bare 1-65535 port, so an imported
// endpoint string can't smuggle extra pf directives into the ruleset.
func validatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

// enforcesDNS reports whether rs produces a DNS protection section. With no
// known servers it is pending (nothing to allow, so blocking all DNS would
// just break name resolution) unless a tunnel is reconnecting, in which case
// all DNS stays blocked except the DNSLookupServers.
func (rs Ruleset) enforcesDNS() bool {
	if !rs.DNSProtection {
		return false
	}
	if len(rs.DNSServers) > 0 {
		return true
	}
	for _, t := range rs.Tunnels {
		if t.InterfaceName == "" {
			return true
		}
	}
	return false
}

// BuildRules renders rs as the pf anchor ruleset. It returns "" when rs
// enforces nothing. Pure: no pf or system state is touched.
func BuildRules(rs Ruleset) (string, error) {
	dns := rs.enforcesDNS()
	if !rs.KillSwitch && !dns {
		return "", nil
	}
	var ifaces []string
	for _, t := range rs.Tunnels {
		if t.InterfaceName == "" {
			continue
		}
		if !validIfaceName.MatchString(t.InterfaceName) {
			return "", fmt.Errorf("invalid interface name %q", t.InterfaceName)
		}
		ifaces = append(ifaces, t.InterfaceName)
	}

	var b strings.Builder
	b.WriteString("# LockPlus\n")
	if rs.KillSwitch {
		// Reassemble fragments first: fragments can't match the port-qualified
		// pass rules below and would otherwise be dropped by "block drop".
		b.WriteString("scrub in all fragment reassemble\n")
		b.WriteString("scrub out all fragment reassemble\n")
	}
	b.WriteString("pass quick on lo0 all\n")
	for _, s := range rs.DNSLookupServers {
		if net.ParseIP(s) == nil {
			return "", fmt.Errorf("invalid DNS lookup server IP %q", s)
		}
		fmt.Fprintf(&b, "pass out quick proto {tcp, udp} to %s port 53 flags any\n", s)
	}

	// DNS protection precedes the per-interface passes so it also restricts
	// DNS sent through a tunnel. "flags any": DNS-over-TCP may be a
	// connection established before the rules were loaded.
	if dns {
		for _, s := range rs.DNSServers {
			if net.ParseIP(s) == nil {
				return "", fmt.Errorf("invalid DNS server IP %q", s)
			}
			for _, ifc := range ifaces {
				fmt.Fprintf(&b, "pass out quick on %s proto {tcp, udp} to %s port 53 flags any\n", ifc, s)
			}
		}
		b.WriteString("block drop out quick proto {tcp, udp} to any port 53\n")
	}

	if !rs.KillSwitch {
		return b.String(), nil
	}

	for _, t := range rs.Tunnels {
		proto := "udp"
		flags := ""
		if strings.HasPrefix(t.Proto, "tcp") {
			// Default TCP flags S/SA only match a SYN; the connection to the
			// server is usually already established when rules load.
			proto, flags = "tcp", " flags any"
		}
		for _, ep := range t.Endpoints {
			ip, port, err := net.SplitHostPort(ep)
			if err != nil {
				ip, port = ep, "" // bare IP
			}
			if ip == "" {
				continue
			}
			if net.ParseIP(ip) == nil {
				return "", fmt.Errorf("invalid endpoint IP %q", ip)
			}
			if port == "" {
				fmt.Fprintf(&b, "pass out quick proto %s to %s%s\n", proto, ip, flags)
				continue
			}
			if err := validatePort(port); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "pass out quick proto %s to %s port %s%s\n", proto, ip, port, flags)
		}
	}
	b.WriteString("pass out quick proto udp from any port 68 to any port 67\n")
	b.WriteString("pass out quick proto udp from any port 546 to any port 547\n")
	// IPv6 router/neighbour solicitation and advertisement only: without
	// ND the link's IPv6 (and DHCPv6 above) can't work.
	b.WriteString("pass quick inet6 proto ipv6-icmp icmp6-type {133, 134, 135, 136}\n")
	for _, ifc := range ifaces {
		fmt.Fprintf(&b, "pass quick on %s all\n", ifc)
	}
	b.WriteString("block drop out all\n")
	b.WriteString("block drop in all\n")
	return b.String(), nil
}
