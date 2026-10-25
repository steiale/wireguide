package helper

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/firewall"
	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/ovpn"
	"github.com/steiale/wireguide/internal/reconnect"
)

// multiProfile has a hostname, an IP-literal and a <connection> hostname
// remote.
const multiProfile = "client\nproto udp\nremote vpn1.example.com 1194\nremote 198.51.100.9 443 tcp\n<connection>\nremote vpn2.example.com\nproto tcp\n</connection>\n"

const singleProfile = "client\nproto udp\nremote vpn1.example.com 1194\n"

// passedEndpoints flattens a ruleset's endpoint passes as "proto ep", sorted
// and deduplicated, plus its interfaces.
func passedEndpoints(rs firewall.Ruleset) (eps, ifaces []string) {
	for _, tn := range rs.Tunnels {
		if tn.InterfaceName != "" && !slices.Contains(ifaces, tn.InterfaceName) {
			ifaces = append(ifaces, tn.InterfaceName)
		}
		for _, ep := range tn.Endpoints {
			if e := tn.Proto + " " + ep; !slices.Contains(eps, e) {
				eps = append(eps, e)
			}
		}
	}
	slices.Sort(eps)
	return eps, ifaces
}

func stubResolver(t *testing.T, answers map[string][]string) {
	t.Helper()
	oldRes, oldLookup := systemResolvers, resolveHost
	t.Cleanup(func() { systemResolvers, resolveHost = oldRes, oldLookup })
	systemResolvers = func() []string { return []string{"192.168.1.1"} }
	resolveHost = func(_ context.Context, host string) ([]string, error) { return answers[host], nil }
}

// M1: a reconnecting (held or pending) tunnel keeps the helper alive, and a
// shutdown timer that fires while one is reconnecting clears itself so the
// rearm works once the tunnel is gone.
func TestShutdownTimerRespectsReconnectHold(t *testing.T) {
	h, _ := newTestHelper(t)
	old := shutdownGrace
	shutdownGrace = 20 * time.Millisecond
	defer func() { shutdownGrace = old }()

	h.fwHeld["vpn"] = 1
	if _, active := h.anyTunnelActive(); !active {
		t.Fatal("held tunnel not counted as active")
	}
	delete(h.fwHeld, "vpn")
	h.fwPending["vpn"] = true
	if _, active := h.anyTunnelActive(); !active {
		t.Fatal("pending tunnel not counted as active")
	}
	delete(h.fwPending, "vpn")
	if _, active := h.anyTunnelActive(); active {
		t.Fatal("idle helper counted as active")
	}

	h.startShutdownTimer() // GUI gone, nothing up: armed
	h.mu.Lock()
	h.fwHeld["vpn"] = 1 // a reconnect starts within the grace window
	armed := h.shutdownTimer != nil
	h.mu.Unlock()
	if !armed {
		t.Fatal("timer not armed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		cleared := h.shutdownTimer == nil
		h.mu.Unlock()
		if cleared {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("aborted timer not cleared")
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.rearmShutdownIfIdle()
	h.mu.Lock()
	if h.shutdownTimer != nil {
		h.mu.Unlock()
		t.Fatal("rearmed while a tunnel is reconnecting")
	}
	delete(h.fwHeld, "vpn")
	h.mu.Unlock()
	h.rearmShutdownIfIdle()
	h.mu.Lock()
	rearmed := h.shutdownTimer
	h.mu.Unlock()
	if rearmed == nil {
		t.Fatal("not rearmed once the reconnect ended")
	}
	rearmed.Stop()
}

// M2 + onOVPNGone: a failed block-lifting connect always drops its pending
// hold; it re-blocks only under the kill switch, and leaves a retry
// sequence's hold alone.
func TestOVPNGoneEndsPendingHold(t *testing.T) {
	h, fw := newTestHelper(t)
	h.ovpnManager = &fakeOVPN{statuses: map[string]domain.ConnectionStatus{}}
	gone := domain.ConnectionStatus{TunnelName: "work", State: domain.StateError, ErrorMessage: "TLS handshake failed"}

	// Kill switch turned off mid-attempt: no block, and no leaked hold.
	h.fwPending["work"] = true
	h.onOVPNGone(gone)
	if h.fwPending["work"] || len(h.fwBlocked) != 0 {
		t.Fatalf("pending=%v blocked=%v", h.fwPending, h.fwBlocked)
	}
	if got := fw.last(); !reflect.DeepEqual(got, firewall.Ruleset{}) {
		t.Fatalf("ruleset = %+v", got)
	}
	// Turning the kill switch back on must not resurrect a hold.
	if _, err := h.handleSetKillSwitch([]byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	if got := fw.last(); !reflect.DeepEqual(got, firewall.Ruleset{}) {
		t.Fatalf("hidden hold resurrected: %+v", got)
	}

	// Under the kill switch the block comes back.
	h.fwPending["work"] = true
	h.onOVPNGone(gone)
	if h.fwPending["work"] || h.fwBlocked["work"] != domain.ProtocolOpenVPN {
		t.Fatalf("pending=%v blocked=%v", h.fwPending, h.fwBlocked)
	}
	if got := fw.last(); !reflect.DeepEqual(got, firewall.Ruleset{KillSwitch: true}) {
		t.Fatalf("ruleset = %+v", got)
	}

	// A retry sequence's hold is not touched; nor is a still-live entry.
	delete(h.fwBlocked, "work")
	h.fwHeld["work"], h.fwPending["work"] = 1, true
	h.onOVPNGone(gone)
	if !h.fwPending["work"] || len(h.fwBlocked) != 0 {
		t.Fatalf("held tunnel changed: pending=%v blocked=%v", h.fwPending, h.fwBlocked)
	}
}

// liftBlockForConnect turns a block into a pending hold passing the
// tunnel's literal and pre-resolved endpoints, and does nothing for an
// unblocked tunnel. L4: the lookup itself runs without connectMu.
func TestLiftBlockForConnect(t *testing.T) {
	h, fw := newTestHelper(t)
	h.policy = fwPolicy{killSwitch: true}
	h.activeOVPNCfgs["work"] = []byte(multiProfile)

	if h.liftBlockForConnect("work", nil) {
		t.Fatal("lifted a block that does not exist")
	}
	if len(h.fwPending) != 0 {
		t.Fatal("pending hold without a block")
	}

	h.fwBlocked["work"] = domain.ProtocolOpenVPN
	stubResolver(t, map[string][]string{"vpn1.example.com": {"203.0.113.1"}, "vpn2.example.com": {"203.0.113.2"}})
	req := &ipc.ConnectRequest{Protocol: domain.ProtocolOpenVPN, TunnelName: "work", OVPNConfig: multiProfile}
	h.connectMu.Lock()
	got := make(chan []literalEndpoint, 1)
	go func() { got <- h.preResolveConnect(req) }()
	var resolved []literalEndpoint
	select {
	case resolved = <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("preResolveConnect waited for connectMu")
	}
	h.connectMu.Unlock()
	if len(fw.last().DNSLookupServers) != 0 {
		t.Fatal("lookup window left open")
	}

	if !h.liftBlockForConnect("work", resolved) {
		t.Fatal("block not lifted")
	}
	if !h.fwPending["work"] || len(h.fwBlocked) != 0 {
		t.Fatalf("pending=%v blocked=%v", h.fwPending, h.fwBlocked)
	}
	eps, _ := passedEndpoints(fw.last())
	want := []string{"tcp 198.51.100.9:443", "tcp 203.0.113.2:1194", "udp 203.0.113.1:1194"}
	if !reflect.DeepEqual(eps, want) {
		t.Fatalf("passed %v, want %v", eps, want)
	}
}

// L1: CONNECTED before the utun is known keeps the pending hold; the
// interface arriving drops it.
func TestPendingHoldKeptUntilInterfaceKnown(t *testing.T) {
	h, fw := newTestHelper(t)
	h.policy = fwPolicy{killSwitch: true}
	h.activeOVPNCfgs["work"] = []byte("client\nremote 203.0.113.5 1194\n")
	fo := &fakeOVPN{statuses: map[string]domain.ConnectionStatus{"work": {TunnelName: "work", State: domain.StateConnected}}}
	h.ovpnManager = fo
	h.fwPending["work"] = true

	h.onOVPNActiveChange("work", true)
	if !h.fwPending["work"] {
		t.Fatal("pending hold dropped before the interface is known")
	}
	if eps, _ := passedEndpoints(fw.last()); !reflect.DeepEqual(eps, []string{"udp 203.0.113.5:1194"}) {
		t.Fatalf("endpoint not passed in the gap: %v", eps)
	}

	fo.mu.Lock()
	fo.statuses["work"] = domain.ConnectionStatus{TunnelName: "work", State: domain.StateConnected, InterfaceName: "utun7"}
	fo.remotes = []ovpn.RemoteEndpoint{{TunnelName: "work", InterfaceName: "utun7", Proto: "udp", Addr: "203.0.113.5:1194"}}
	fo.mu.Unlock()
	h.onOVPNActiveChange("work", true) // setInterface's re-apply
	if h.fwPending["work"] {
		t.Fatal("pending hold kept after the interface is known")
	}
	if _, ifaces := passedEndpoints(fw.last()); !reflect.DeepEqual(ifaces, []string{"utun7"}) {
		t.Fatalf("interface not passed: %v", ifaces)
	}
}

// L3: a live multi-remote OpenVPN tunnel (also during openvpn's own
// RECONNECTING) passes every remote: literals and connect-time resolved
// hostnames. A single-remote tunnel passes only its current remote.
func TestMultiRemoteLivePassesAllRemotes(t *testing.T) {
	h, fw := newTestHelper(t)
	h.policy = fwPolicy{killSwitch: true}
	fo := &fakeOVPN{
		statuses: map[string]domain.ConnectionStatus{"work": {TunnelName: "work", State: domain.StateConnecting, InterfaceName: "utun7"}},
		remotes:  []ovpn.RemoteEndpoint{{TunnelName: "work", InterfaceName: "utun7", Proto: "udp", Addr: "203.0.113.1:1194"}},
	}
	h.ovpnManager = fo
	h.activeOVPNCfgs["work"] = []byte(multiProfile)
	h.fwEndpoints["work"] = cachedEndpoints{resolved: []literalEndpoint{{"203.0.113.1:1194", "udp"}, {"203.0.113.2:1194", "tcp"}}}

	if err := h.applyFirewall("test"); err != nil {
		t.Fatal(err)
	}
	eps, ifaces := passedEndpoints(fw.last())
	want := []string{"tcp 198.51.100.9:443", "tcp 203.0.113.2:1194", "udp 203.0.113.1:1194"}
	if !reflect.DeepEqual(eps, want) || !reflect.DeepEqual(ifaces, []string{"utun7"}) {
		t.Fatalf("passed %v on %v, want %v on utun7", eps, ifaces, want)
	}
	if c := h.fwEndpoints["work"]; len(c.resolved) != 2 {
		t.Fatalf("apply dropped the resolved remotes: %+v", c)
	}

	h.activeOVPNCfgs["work"] = []byte(singleProfile)
	if err := h.applyFirewall("test"); err != nil {
		t.Fatal(err)
	}
	if eps, _ := passedEndpoints(fw.last()); !reflect.DeepEqual(eps, []string{"udp 203.0.113.1:1194"}) {
		t.Fatalf("single remote passed %v", eps)
	}
}

// L3: a multi-remote connect resolves its hostname remotes before
// connectMu and keeps them for the tunnel's lifetime.
func TestMultiRemoteConnectResolves(t *testing.T) {
	h, _ := newTestHelper(t)
	h.policy = fwPolicy{killSwitch: true}
	h.ovpnBinary = t.TempDir() // exists
	fo := &fakeOVPN{statuses: map[string]domain.ConnectionStatus{}}
	h.ovpnManager = fo
	stubResolver(t, map[string][]string{"vpn1.example.com": {"203.0.113.1"}, "vpn2.example.com": {"203.0.113.2"}})

	params := []byte(`{"protocol":"openvpn","tunnel_name":"work","ovpn_config":` + jsonString(multiProfile) + `}`)
	if _, err := h.handleConnect(params); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fo.connected, []string{"work"}) {
		t.Fatalf("connected %v", fo.connected)
	}
	_ = h.applyFirewall("other-tunnel-event") // must not prune them before CONNECTED
	c := h.fwEndpoints["work"]
	if !reflect.DeepEqual(c.resolved, []literalEndpoint{{"203.0.113.1:1194", "udp"}, {"203.0.113.2:1194", "tcp"}}) {
		t.Fatalf("resolved = %+v", c.resolved)
	}
}

// L3 watchdog: a multi-remote tunnel stuck in openvpn's own reconnect for
// ovpnStuckTimeout after having been CONNECTED is recycled; never while
// awaiting credentials, never a single-remote tunnel. The death then takes
// the reconnect path (held, every remote passed) or, without
// auto-reconnect, the fail-closed block.
func TestOVPNWatchdog(t *testing.T) {
	h, fw := newTestHelper(t)
	h.monitor = reconnect.NewMonitor(h.manager, nil, nil, reconnect.DefaultConfig())
	h.policy = fwPolicy{killSwitch: true}
	t0 := time.Now()
	fo := &fakeOVPN{statuses: map[string]domain.ConnectionStatus{
		"work": {TunnelName: "work", State: domain.StateConnecting, ConnectedAt: t0.Add(-time.Hour)},
	}}
	h.ovpnManager = fo
	h.activeOVPNCfgs["work"] = []byte(multiProfile)

	// Awaiting credentials: never fires, and the clock restarts after.
	fo.awaiting = true
	h.checkOVPNWatchdog(t0)
	h.checkOVPNWatchdog(t0.Add(10 * time.Minute))
	fo.awaiting = false
	h.checkOVPNWatchdog(t0.Add(11 * time.Minute))
	h.checkOVPNWatchdog(t0.Add(12 * time.Minute))
	if len(fo.recycled) != 0 {
		t.Fatalf("recycled while awaiting credentials or too early: %v", fo.recycled)
	}
	h.checkOVPNWatchdog(t0.Add(13 * time.Minute))
	if !slices.Equal(fo.recycled, []string{"work"}) {
		t.Fatalf("recycled %v, want [work]", fo.recycled)
	}

	// Never connected (first connect attempt): no.
	fo.recycled = nil
	fo.statuses["work"] = domain.ConnectionStatus{TunnelName: "work", State: domain.StateConnecting}
	h.checkOVPNWatchdog(t0)
	h.checkOVPNWatchdog(t0.Add(time.Hour))
	if len(fo.recycled) != 0 {
		t.Fatalf("recycled a never-connected tunnel: %v", fo.recycled)
	}
	// Single-remote stuck after CONNECTED: yes (a fresh process re-resolves a
	// hostname remote that --persist-remote-ip would otherwise pin forever).
	fo.statuses["work"] = domain.ConnectionStatus{TunnelName: "work", State: domain.StateConnecting, ConnectedAt: t0}
	h.activeOVPNCfgs["work"] = []byte(singleProfile)
	h.checkOVPNWatchdog(t0)
	h.checkOVPNWatchdog(t0.Add(time.Hour))
	if !slices.Equal(fo.recycled, []string{"work"}) {
		t.Fatalf("single-remote: recycled %v, want [work]", fo.recycled)
	}
	fo.recycled = nil

	// The recycled process's death with auto-reconnect: held, with every
	// remote (literal + resolved) passed for the fresh process.
	delete(fo.statuses, "work")
	h.activeOVPNCfgs["work"] = []byte(multiProfile)
	h.autoReconnect["work"] = true
	h.fwEndpoints["work"] = cachedEndpoints{
		passes:   []firewall.KillSwitchTunnel{{Proto: "udp", Endpoints: []string{"203.0.113.1:1194"}}},
		resolved: []literalEndpoint{{"203.0.113.1:1194", "udp"}, {"203.0.113.2:1194", "tcp"}},
	}
	h.onOVPNDied("work")
	if !h.fwPending["work"] || len(h.fwBlocked) != 0 {
		t.Fatalf("pending=%v blocked=%v", h.fwPending, h.fwBlocked)
	}
	eps, _ := passedEndpoints(fw.last())
	if want := []string{"tcp 198.51.100.9:443", "tcp 203.0.113.2:1194", "udp 203.0.113.1:1194"}; !reflect.DeepEqual(eps, want) {
		t.Fatalf("held passes %v, want %v", eps, want)
	}

	// Without auto-reconnect: fail-closed block.
	delete(h.fwPending, "work")
	h.autoReconnect["work"] = false
	h.onOVPNDied("work")
	if h.fwBlocked["work"] != domain.ProtocolOpenVPN || h.fwPending["work"] {
		t.Fatalf("pending=%v blocked=%v", h.fwPending, h.fwBlocked)
	}
	if got := fw.last(); !reflect.DeepEqual(got, firewall.Ruleset{KillSwitch: true}) {
		t.Fatalf("ruleset = %+v", got)
	}
}

// M4: ActiveTunnels reports reconnecting and blocked tunnels as protected.
func TestActiveTunnelsReportsProtected(t *testing.T) {
	h, _ := newTestHelper(t)
	h.ovpnManager = &fakeOVPN{statuses: map[string]domain.ConnectionStatus{"live": {TunnelName: "live", State: domain.StateConnected}}}
	h.fwHeld["held"] = 1
	h.fwPending["pending"] = true
	h.fwPending["live"] = true
	h.fwBlocked["blocked"] = domain.ProtocolWireGuard
	res, err := h.handleActiveTunnels(nil)
	if err != nil {
		t.Fatal(err)
	}
	got := res.(ipc.ActiveTunnelsResponse)
	if !reflect.DeepEqual(got.Names, []string{"live"}) || !reflect.DeepEqual(got.Protected, []string{"blocked", "held", "pending"}) {
		t.Fatalf("got %+v", got)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
