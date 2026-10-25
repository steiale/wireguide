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
	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/network"
	"github.com/steiale/wireguide/internal/ovpn"
	"github.com/steiale/wireguide/internal/storage"
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
//     A multi-remote OpenVPN profile (no --persist-remote-ip) passes every
//     remote while active, since openvpn may fail over to any of them in its
//     own reconnect: IP literals plus hostname remotes resolved at connect
//     time (no DNS window during that internal reconnect; the watchdog in
//     helper.go recycles a process stuck there).
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
	// resolved holds the configured hostname endpoints as resolved at the
	// last connect or reconnect attempt, passed while the tunnel is held
	// and, for a multi-remote OpenVPN tunnel, while it is active.
	resolved []literalEndpoint
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

// endpointPassesLocked returns every server pass known for name, as fresh
// slices: the cached (last connected) passes, every configured IP-literal
// remote (a multi-remote profile can come back on any of them) and the
// resolved hostname remotes. Caller holds h.mu.
func (h *Helper) endpointPassesLocked(name string) []firewall.KillSwitchTunnel {
	var out cachedEndpoints
	c := h.fwEndpoints[name]
	for _, p := range c.passes {
		for _, ep := range p.Endpoints {
			out.addPass(p.Proto, ep)
		}
	}
	literal, _ := h.configuredEndpointsLocked(name)
	for _, l := range literal {
		out.addPass(l.proto, l.ep)
	}
	for _, r := range c.resolved {
		out.addPass(r.proto, r.ep)
	}
	return out.passes
}

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
		c := h.fwEndpoints[name] // keeps resolved
		c.passes = []firewall.KillSwitchTunnel{{Proto: tunnels[i].Proto, Endpoints: slices.Clone(tunnels[i].Endpoints)}}
		c.hostname = len(hosts) > 0
		h.fwEndpoints[name] = c
	}
	rs := firewall.Ruleset{KillSwitch: pol.killSwitch, DNSProtection: pol.dnsProtection, DNSServers: dns, Tunnels: tunnels}
	// A live multi-remote OpenVPN tunnel: every remote stays passed, so its
	// own failover during RECONNECTING can reach any of them.
	for i, name := range names {
		if i > 0 && names[i-1] == name || !h.isMultiRemoteOVPNLocked(name) {
			continue
		}
		for _, p := range h.endpointPassesLocked(name) {
			rs.Tunnels = append(rs.Tunnels, firewall.KillSwitchTunnel{Proto: p.Proto, Endpoints: p.Endpoints})
		}
	}
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
		passes := h.endpointPassesLocked(name)
		for _, p := range passes {
			rs.Tunnels = append(rs.Tunnels, firewall.KillSwitchTunnel{Proto: p.Proto, Endpoints: p.Endpoints})
		}
		if len(passes) == 0 {
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
		// An OpenVPN tunnel keeps its connect-time resolved remotes while it
		// is wanted, including between Connect and CONNECTED.
		_, wanted := h.activeOVPNCfgs[name]
		if !slices.Contains(names, name) && !h.isHeldLocked(name) && !wanted {
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

// lookupBudget bounds one resolveEndpoints call in total (each lookup is
// also capped at lookupTimeout); vars for tests.
var (
	lookupBudget  = 10 * time.Second
	lookupTimeout = 5 * time.Second
)

// resolveEndpoints resolves hosts to ip:port literals. It does no firewall
// work: callers that need port 53 open wrap it in openLookupWindow.
func resolveEndpoints(name string, hosts []hostPort) []literalEndpoint {
	budget, cancelBudget := context.WithTimeout(context.Background(), lookupBudget)
	defer cancelBudget()
	var out []literalEndpoint
	for _, hp := range hosts {
		ctx, cancel := context.WithTimeout(budget, lookupTimeout)
		ips, err := resolveHost(ctx, hp.host)
		cancel()
		if err != nil {
			slog.Warn("resolving endpoint failed", "tunnel", name, "host", hp.host, "error", err)
			continue
		}
		for _, ip := range ips {
			out = append(out, literalEndpoint{net.JoinHostPort(ip, hp.port), hp.proto})
		}
	}
	return out
}

// openLookupWindow passes port 53 to the system resolvers (only) while
// name's endpoints are resolved; the caller deletes dnsLookups[name] and
// re-applies when done.
func (h *Helper) openLookupWindow(name string) {
	resolvers := systemResolvers()
	h.mu.Lock()
	h.dnsLookups[name] = resolvers
	h.mu.Unlock()
	_ = h.applyFirewall("endpoint-lookup")
}

// storeResolvedLocked records name's resolved hostname endpoints (kept if
// the lookup found nothing). Caller holds h.mu.
func (h *Helper) storeResolvedLocked(name string, answers []literalEndpoint) {
	c := h.fwEndpoints[name]
	c.hostname = true
	if len(answers) > 0 {
		c.resolved = answers
	}
	h.fwEndpoints[name] = c
}

// passResolvedHostnames resolves a held tunnel's hostname endpoints and adds
// the answers to its pass list before a reconnect attempt, so the attempt
// (which resolves the same names moments later, from mDNSResponder's cache)
// can reach the server. Port 53 to the system resolvers is opened only for
// the duration of these lookups. Never called under connectMu.
func (h *Helper) passResolvedHostnames(name string) {
	h.mu.Lock()
	_, hosts := h.configuredEndpointsLocked(name)
	h.mu.Unlock()
	if len(hosts) == 0 {
		return
	}
	h.openLookupWindow(name)
	answers := resolveEndpoints(name, hosts)
	h.mu.Lock()
	delete(h.dnsLookups, name)
	h.storeResolvedLocked(name, answers)
	h.mu.Unlock()
	_ = h.applyFirewall("reconnect-resolve")
}

// connectHosts returns the hostname endpoints of a connect request and
// whether it is a multi-remote OpenVPN profile. Unvalidated requests (the
// connect itself rejects them) yield nothing.
func connectHosts(req *ipc.ConnectRequest) (name string, hosts []hostPort, multi bool) {
	if domain.NormalizeProtocol(req.Protocol) == domain.ProtocolOpenVPN {
		if storage.ValidateTunnelName(req.TunnelName) != nil || ovpn.ValidateOVPN([]byte(req.OVPNConfig)) != nil {
			return "", nil, false
		}
		cfg, err := ovpn.ParseOVPN([]byte(req.OVPNConfig))
		if err != nil {
			return "", nil, false
		}
		for _, r := range cfg.Remotes {
			if net.ParseIP(r.Host) == nil {
				hosts = append(hosts, hostPort{r.Host, r.Port, r.Proto})
			}
		}
		return req.TunnelName, hosts, len(cfg.Remotes) > 1
	}
	if req.Config == nil || storage.ValidateTunnelName(req.Config.Name) != nil {
		return "", nil, false
	}
	for _, p := range req.Config.Peers {
		host, port, err := net.SplitHostPort(p.Endpoint)
		if err == nil && net.ParseIP(host) == nil {
			hosts = append(hosts, hostPort{host, port, "udp"})
		}
	}
	return req.Config.Name, hosts, false
}

// preResolveConnect resolves a connect request's hostname endpoints BEFORE
// handleConnect takes connectMu (a lookup can take seconds, and Disconnect
// must not wait for it). Needed when the tunnel is blocked (the lifted
// block passes only its endpoints) or is a multi-remote OpenVPN profile
// (every remote is passed while active). Under the kill switch port 53 to
// the system resolvers is passed for the lookup only. The caller re-checks
// the block under connectMu (liftBlockForConnect).
func (h *Helper) preResolveConnect(req *ipc.ConnectRequest) []literalEndpoint {
	name, hosts, multi := connectHosts(req)
	if name == "" || len(hosts) == 0 {
		return nil
	}
	h.mu.Lock()
	_, blocked := h.fwBlocked[name]
	ks := h.policy.killSwitch
	h.mu.Unlock()
	if !blocked && !multi {
		return nil
	}
	if ks {
		h.openLookupWindow(name)
	}
	answers := resolveEndpoints(name, hosts)
	if ks {
		h.mu.Lock()
		delete(h.dnsLookups, name)
		h.mu.Unlock()
		_ = h.applyFirewall("connect-resolve")
	}
	return answers
}
