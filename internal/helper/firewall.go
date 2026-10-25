package helper

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sort"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/firewall"
	"github.com/steiale/wireguide/internal/network"
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
//   - tunnels up (WireGuard connected; OpenVPN active, including while
//     openvpn itself is RECONNECTING): block-all except their interfaces
//     and endpoints; DNS protection allows only the tunnels' DNS servers.
//   - a tunnel reconnecting (held by the reconnect monitor, or pending
//     between its death and the monitor taking over): its server endpoints
//     (cached and configured) stay passed on any interface. While a hostname
//     endpoint is being re-resolved, port 53 to the system resolvers only is
//     passed for the duration of that lookup. Everything else stays blocked.
//   - a tunnel that died unexpectedly and is not being reconnected, while
//     the kill switch is on: blocked (fail closed, nothing passed but
//     loopback/DHCP/ND) until the user disconnects or reconnects it, or
//     turns the kill switch off. The GUI shows it as blocked.
//   - nothing up, reconnecting or blocked: our rules are removed.

type fwPolicy struct {
	killSwitch    bool
	dnsProtection bool
}

// cachedEndpoints remembers a tunnel's server passes so they can be kept
// while the tunnel is down and reconnecting.
type cachedEndpoints struct {
	passes   []firewall.KillSwitchTunnel // endpoint-only entries (no interface)
	hostname bool                        // configured endpoint is a hostname that needs DNS
}

// addPass adds ep (proto) to c unless already present.
func (c *cachedEndpoints) addPass(proto, ep string) {
	for i := range c.passes {
		if c.passes[i].Proto == proto {
			if !slices.Contains(c.passes[i].Endpoints, ep) {
				c.passes[i].Endpoints = append(c.passes[i].Endpoints, ep)
			}
			return
		}
	}
	c.passes = append(c.passes, firewall.KillSwitchTunnel{Proto: proto, Endpoints: []string{ep}})
}

// blockedMessage is the status text of a tunnel kept blocked (item: the
// GUI's error line on the tunnel card).
const blockedMessage = "Connection lost. The kill switch is blocking all traffic until you reconnect or disconnect this tunnel."

// isHeldLocked reports whether name is in a reconnect hold. Caller holds h.mu.
func (h *Helper) isHeldLocked(name string) bool {
	return h.fwHeld[name] > 0 || h.fwPending[name]
}

// liveTunnels returns every tunnel that is up as a kill switch entry,
// sorted by name, and the union of their DNS servers. OpenVPN tunnels come
// from ActiveRemotes, which keeps an active tunnel while openvpn itself is
// RECONNECTING (ping-restart, SIGUSR1): dropping it there would delete its
// endpoint pass, or flush everything if it was the only tunnel.
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
		statuses := map[string]domain.ConnectionStatus{}
		for _, st := range h.ovpnManager.AllStatuses() {
			statuses[st.TunnelName] = st
		}
		seen := map[string]bool{}
		for _, r := range h.ovpnManager.ActiveRemotes() {
			seen[r.TunnelName] = true
			all = append(all, named{r.TunnelName, firewall.KillSwitchTunnel{InterfaceName: r.InterfaceName, Proto: r.Proto, Endpoints: []string{r.Addr}}})
			addDNS(statuses[r.TunnelName].DNSServers)
		}
		for name, st := range statuses {
			if seen[name] || st.State != domain.StateConnected || st.InterfaceName == "" {
				continue
			}
			slog.Warn("OpenVPN remote unknown, kill switch cannot pass its transport", "tunnel", name)
			all = append(all, named{name, firewall.KillSwitchTunnel{InterfaceName: st.InterfaceName}})
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
		delete(h.fwBlocked, name) // up again: no longer a dead tunnel
		_, hosts := h.configuredEndpointsLocked(name)
		h.fwEndpoints[name] = cachedEndpoints{
			passes:   []firewall.KillSwitchTunnel{{Proto: tunnels[i].Proto, Endpoints: slices.Clone(tunnels[i].Endpoints)}},
			hostname: len(hosts) > 0,
		}
	}
	rs := firewall.Ruleset{KillSwitch: pol.killSwitch, DNSProtection: pol.dnsProtection, DNSServers: dns, Tunnels: tunnels}
	held := make([]string, 0, len(h.fwHeld)+len(h.fwPending))
	for name := range h.fwHeld {
		held = append(held, name)
	}
	for name := range h.fwPending {
		if h.fwHeld[name] == 0 {
			held = append(held, name)
		}
	}
	sort.Strings(held)
	for _, name := range held {
		if slices.Contains(names, name) {
			continue
		}
		// Cached (last connected) passes plus every configured IP-literal
		// remote, so a multi-remote profile can come back on any of them.
		c := h.fwEndpoints[name]
		literal, _ := h.configuredEndpointsLocked(name)
		for _, l := range literal {
			c.addPass(l.proto, l.ep)
		}
		for _, p := range c.passes {
			if len(p.Endpoints) > 0 {
				rs.Tunnels = append(rs.Tunnels, firewall.KillSwitchTunnel{Proto: p.Proto, Endpoints: slices.Clone(p.Endpoints)})
			}
		}
		if len(c.passes) == 0 {
			// Nothing known yet: still keep the ruleset (blocked) rather than
			// flushing it while the tunnel is down.
			rs.Tunnels = append(rs.Tunnels, firewall.KillSwitchTunnel{})
		}
	}
	for _, name := range slices.Sorted(maps.Keys(h.dnsLookups)) {
		for _, s := range h.dnsLookups[name] {
			if !slices.Contains(rs.DNSLookupServers, s) {
				rs.DNSLookupServers = append(rs.DNSLookupServers, s)
			}
		}
	}
	for name := range h.fwEndpoints {
		if !slices.Contains(names, name) && !h.isHeldLocked(name) {
			delete(h.fwEndpoints, name)
		}
	}
	blocked := pol.killSwitch && len(h.fwBlocked) > 0
	h.mu.Unlock()

	if len(rs.Tunnels) == 0 && !blocked {
		rs = firewall.Ruleset{} // nothing up, reconnecting or blocked: remove our rules
	}
	if err := h.firewall.Apply(rs); err != nil {
		slog.Error("applying firewall policy failed", "reason", reason, "error", err)
		return err
	}
	return nil
}

// holdFirewall keeps tunnelName's endpoints passed while it reconnects.
// Used as the reconnect monitor's suspend callback. Holds are counted: an
// old retry sequence that outlives its replacement (triggerReconnectTunnel
// gives up waiting after 5s) releases only its own hold. The sequence takes
// over a pending hold from the tunnel's death.
func (h *Helper) holdFirewall(tunnelName string) error {
	h.mu.Lock()
	h.fwHeld[tunnelName]++
	delete(h.fwPending, tunnelName)
	delete(h.fwBlocked, tunnelName) // reconnecting again: endpoints passed
	h.mu.Unlock()
	return h.applyFirewall("reconnect-hold")
}

// releaseFirewall ends one reconnect hold of tunnelName. Used as the
// reconnect monitor's resume callback. When the last hold ends without the
// tunnel being back up and the user still wants it (the sequence gave up),
// the kill switch keeps it blocked instead of dropping protection.
func (h *Helper) releaseFirewall(tunnelName string) error {
	live := h.tunnelIsUp(tunnelName)
	h.mu.Lock()
	if h.fwHeld[tunnelName] > 1 {
		h.fwHeld[tunnelName]--
	} else {
		delete(h.fwHeld, tunnelName)
		if !live && !h.fwPending[tunnelName] && h.autoReconnect[tunnelName] && h.policy.killSwitch {
			slog.Warn("reconnect ended without the tunnel, kill switch keeps it blocked", "tunnel", tunnelName)
			h.fwBlocked[tunnelName] = h.protocolLocked(tunnelName)
		}
	}
	h.mu.Unlock()
	return h.applyFirewall("reconnect-release")
}

// tunnelIsUp reports whether name is up in either manager.
func (h *Helper) tunnelIsUp(name string) bool {
	if h.manager != nil && h.manager.IsTunnelConnected(name) {
		return true
	}
	return h.ovpnManager != nil && ovpnTunnelHasKnownRemote(h.ovpnManager, name)
}

// protocolLocked returns name's protocol from the cached configs. Caller
// holds h.mu.
func (h *Helper) protocolLocked(name string) domain.Protocol {
	if _, ok := h.activeOVPNCfgs[name]; ok {
		return domain.ProtocolOpenVPN
	}
	return domain.ProtocolWireGuard
}

type hostPort struct{ host, port, proto string }

type literalEndpoint struct{ ep, proto string }

// configuredEndpointsLocked returns the tunnel's configured server
// endpoints: IP literals ready to pass, and hostnames that need resolving.
// For OpenVPN that is every remote of the profile. Caller must hold h.mu.
func (h *Helper) configuredEndpointsLocked(name string) (literal []literalEndpoint, hosts []hostPort) {
	if cfg, ok := h.activeCfgs[name]; ok {
		for _, p := range cfg.Peers {
			host, port, err := net.SplitHostPort(p.Endpoint)
			if err != nil {
				continue
			}
			if net.ParseIP(host) == nil {
				hosts = append(hosts, hostPort{host, port, "udp"})
			} else {
				literal = append(literal, literalEndpoint{net.JoinHostPort(host, port), "udp"})
			}
		}
	}
	if content, ok := h.activeOVPNCfgs[name]; ok {
		if cfg, err := ovpn.ParseOVPN(content); err == nil {
			for _, r := range cfg.Remotes {
				if net.ParseIP(r.Host) == nil {
					hosts = append(hosts, hostPort{r.Host, r.Port, r.Proto})
				} else {
					literal = append(literal, literalEndpoint{net.JoinHostPort(r.Host, r.Port), r.Proto})
				}
			}
		}
	}
	return literal, hosts
}

// resolveHost is net.DefaultResolver.LookupHost; a var for tests.
var resolveHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// systemResolvers is network.SystemResolvers; a var for tests.
var systemResolvers = network.SystemResolvers

// passResolvedHostnames resolves a held tunnel's hostname endpoints and adds
// the answers to its pass list before a reconnect attempt, so the attempt
// (which resolves the same names moments later, from mDNSResponder's cache)
// can reach the server. Port 53 to the system resolvers is opened only for
// the duration of these lookups.
func (h *Helper) passResolvedHostnames(name string) {
	h.mu.Lock()
	_, hosts := h.configuredEndpointsLocked(name)
	h.mu.Unlock()
	if len(hosts) == 0 {
		return
	}
	resolvers := systemResolvers()
	h.mu.Lock()
	h.dnsLookups[name] = resolvers
	h.mu.Unlock()
	_ = h.applyFirewall("reconnect-lookup")

	type answer struct {
		proto, ep string
	}
	var added []answer
	for _, hp := range hosts {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := resolveHost(ctx, hp.host)
		cancel()
		if err != nil {
			slog.Warn("reconnect: resolving endpoint failed", "tunnel", name, "host", hp.host, "error", err)
			continue
		}
		for _, ip := range ips {
			added = append(added, answer{hp.proto, net.JoinHostPort(ip, hp.port)})
		}
	}

	h.mu.Lock()
	delete(h.dnsLookups, name)
	c := h.fwEndpoints[name]
	c.hostname = true
	for _, a := range added {
		c.addPass(a.proto, a.ep)
	}
	// Only kept (and pruned) while the tunnel is held or live.
	h.fwEndpoints[name] = c
	h.mu.Unlock()
	_ = h.applyFirewall("reconnect-resolve")
}
