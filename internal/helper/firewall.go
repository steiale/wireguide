package helper

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/firewall"
	"github.com/steiale/wireguide/internal/ovpn"
)

// Firewall policy model.
//
// The GUI sets the desired kill switch / DNS protection state (policy) via
// Firewall.SetKillSwitch / Firewall.SetDNSProtection, at bootstrap and on
// every toggle. The helper derives the pf ruleset from the policy plus the
// live tunnels and re-applies it on every tunnel transition (connect,
// disconnect, death, reconnect hold/release, policy change):
//
//   - tunnels connected: block-all except their interfaces and endpoints;
//     DNS protection allows only the tunnels' own DNS servers.
//   - a tunnel reconnecting (held by the reconnect monitor): its cached
//     server endpoints stay passed on any interface, plus DNS lookups if an
//     endpoint is a hostname. Everything else stays blocked for the whole
//     outage, never flushed.
//   - no tunnel connected or reconnecting: our rules are removed. Protection
//     follows the tunnels; it is not an "always-on" block.

type fwPolicy struct {
	killSwitch    bool
	dnsProtection bool
}

// cachedEndpoints remembers a tunnel's server so it can be passed while the
// tunnel is down and reconnecting.
type cachedEndpoints struct {
	proto     string
	endpoints []string // "ip:port"
	hostname  bool     // configured endpoint is a hostname that needs DNS
}

// liveTunnels returns every connected tunnel (WireGuard and OpenVPN) as a
// kill switch entry, sorted by name, and the union of their DNS servers.
func (h *Helper) liveTunnels() (names []string, tunnels []firewall.KillSwitchTunnel, dns []string) {
	addDNS := func(entries []string) {
		for _, e := range entries {
			if net.ParseIP(e) != nil && !slices.Contains(dns, e) {
				dns = append(dns, e)
			}
		}
	}
	type named struct {
		name string
		t    firewall.KillSwitchTunnel
	}
	var all []named
	for _, t := range h.manager.ConnectedTunnels() {
		all = append(all, named{t.Name, firewall.KillSwitchTunnel{InterfaceName: t.InterfaceName, Proto: "udp", Endpoints: t.Endpoints}})
		addDNS(t.DNS)
	}
	if h.ovpnManager != nil {
		remotes := map[string]ovpn.RemoteEndpoint{}
		for _, r := range h.ovpnManager.ActiveRemotes() {
			remotes[r.TunnelName] = r
		}
		for _, st := range h.ovpnManager.AllStatuses() {
			if st.State != domain.StateConnected || st.InterfaceName == "" {
				continue
			}
			t := firewall.KillSwitchTunnel{InterfaceName: st.InterfaceName}
			if r, ok := remotes[st.TunnelName]; ok {
				t.Proto, t.Endpoints = r.Proto, []string{r.Addr}
			} else {
				slog.Warn("OpenVPN remote unknown, kill switch cannot pass its transport", "tunnel", st.TunnelName)
			}
			all = append(all, named{st.TunnelName, t})
			addDNS(st.DNSServers)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
	for _, n := range all {
		names = append(names, n.name)
		tunnels = append(tunnels, n.t)
	}
	return names, tunnels, dns
}

// applyFirewall recomputes the ruleset from policy and tunnel state and
// loads it. Called after every transition; failures are logged and
// returned, the previous rules stay loaded.
func (h *Helper) applyFirewall(reason string) error {
	h.fwMu.Lock()
	defer h.fwMu.Unlock()
	select {
	case <-h.done:
		return nil // cleanup owns the firewall now
	default:
	}

	names, tunnels, dns := h.liveTunnels()

	h.mu.Lock()
	pol := h.policy
	for i, name := range names {
		h.fwEndpoints[name] = cachedEndpoints{
			proto:     tunnels[i].Proto,
			endpoints: slices.Clone(tunnels[i].Endpoints),
			hostname:  h.endpointHostsLocked(name) != nil,
		}
	}
	rs := firewall.Ruleset{KillSwitch: pol.killSwitch, DNSProtection: pol.dnsProtection, DNSServers: dns, Tunnels: tunnels}
	held := make([]string, 0, len(h.fwHeld))
	for name := range h.fwHeld {
		held = append(held, name)
	}
	sort.Strings(held)
	for _, name := range held {
		if slices.Contains(names, name) {
			continue
		}
		c := h.fwEndpoints[name]
		rs.Tunnels = append(rs.Tunnels, firewall.KillSwitchTunnel{Proto: c.proto, Endpoints: c.endpoints})
		rs.AllowDNSLookup = rs.AllowDNSLookup || c.hostname
	}
	for name := range h.fwEndpoints {
		if !slices.Contains(names, name) && !h.fwHeld[name] {
			delete(h.fwEndpoints, name)
		}
	}
	h.mu.Unlock()

	if len(rs.Tunnels) == 0 {
		rs = firewall.Ruleset{} // nothing up or reconnecting: remove our rules
	}
	if err := h.firewall.Apply(rs); err != nil {
		slog.Error("applying firewall policy failed", "reason", reason, "error", err)
		return err
	}
	return nil
}

// holdFirewall keeps tunnelName's endpoints passed while it reconnects.
// Used as the reconnect monitor's suspend callback.
func (h *Helper) holdFirewall(tunnelName string) error {
	h.mu.Lock()
	h.fwHeld[tunnelName] = true
	h.mu.Unlock()
	return h.applyFirewall("reconnect-hold")
}

// releaseFirewall ends tunnelName's reconnect hold. Used as the reconnect
// monitor's resume callback.
func (h *Helper) releaseFirewall(tunnelName string) error {
	h.mu.Lock()
	delete(h.fwHeld, tunnelName)
	h.mu.Unlock()
	return h.applyFirewall("reconnect-release")
}

type hostPort struct{ host, port, proto string }

// endpointHostsLocked returns the tunnel's configured endpoints whose host
// is a name rather than an IP literal. Caller must hold h.mu.
func (h *Helper) endpointHostsLocked(name string) []hostPort {
	var out []hostPort
	if cfg, ok := h.activeCfgs[name]; ok {
		for _, p := range cfg.Peers {
			host, port, err := net.SplitHostPort(p.Endpoint)
			if err == nil && net.ParseIP(host) == nil {
				out = append(out, hostPort{host, port, "udp"})
			}
		}
	}
	if content, ok := h.activeOVPNCfgs[name]; ok {
		if cfg, err := ovpn.ParseOVPN(content); err == nil && cfg.Remote != "" {
			host, port, err := net.SplitHostPort(cfg.Remote)
			if err != nil {
				host, port = cfg.Remote, "1194"
			}
			proto := "udp"
			if strings.HasPrefix(cfg.Proto, "tcp") {
				proto = "tcp"
			}
			if net.ParseIP(host) == nil {
				out = append(out, hostPort{host, port, proto})
			}
		}
	}
	return out
}

// passResolvedHostnames resolves a held tunnel's hostname endpoints and adds
// the answers to its pass list before a reconnect attempt, so the attempt
// (which resolves the same names moments later) can reach the server.
func (h *Helper) passResolvedHostnames(name string) {
	h.mu.Lock()
	hosts := h.endpointHostsLocked(name)
	h.mu.Unlock()
	if len(hosts) == 0 {
		return
	}
	var added []string
	for _, hp := range hosts {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := net.DefaultResolver.LookupHost(ctx, hp.host)
		cancel()
		if err != nil {
			slog.Warn("reconnect: resolving endpoint failed", "tunnel", name, "host", hp.host, "error", err)
			continue
		}
		for _, ip := range ips {
			added = append(added, net.JoinHostPort(ip, hp.port))
		}
	}
	if len(added) == 0 {
		return
	}
	h.mu.Lock()
	c := h.fwEndpoints[name]
	c.hostname = true
	if c.proto == "" {
		c.proto = hosts[0].proto
	}
	for _, ep := range added {
		if !slices.Contains(c.endpoints, ep) {
			c.endpoints = append(c.endpoints, ep)
		}
	}
	h.fwEndpoints[name] = c
	h.mu.Unlock()
	_ = h.applyFirewall("reconnect-resolve")
}
