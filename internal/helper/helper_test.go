package helper

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/firewall"
	"github.com/steiale/wireguide/internal/ovpn"
	"github.com/steiale/wireguide/internal/reconnect"
	"github.com/steiale/wireguide/internal/tunnel"
)

type fakeFirewall struct {
	mu      sync.Mutex
	applied []firewall.Ruleset
	fail    bool
}

func (f *fakeFirewall) Apply(rs firewall.Ruleset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("pfctl failed")
	}
	f.applied = append(f.applied, rs)
	return nil
}
func (f *fakeFirewall) Cleanup() error { return nil }

func (f *fakeFirewall) last() firewall.Ruleset {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied[len(f.applied)-1]
}

func newTestHelper(t *testing.T) (*Helper, *fakeFirewall) {
	fw := &fakeFirewall{}
	return &Helper{
		manager:        tunnel.NewManager(t.TempDir()),
		firewall:       fw,
		activeCfgs:     map[string]*domain.WireGuardConfig{},
		activeOVPNCfgs: map[string][]byte{},
		autoReconnect:  map[string]bool{},
		fwHeld:         map[string]int{},
		fwPending:      map[string]bool{},
		fwBlocked:      map[string]domain.Protocol{},
		fwEndpoints:    map[string]cachedEndpoints{},
		dnsLookups:     map[string][]string{},
		ovpnErrors:     map[string]domain.ConnectionStatus{},
		done:           make(chan struct{}),
	}, fw
}

// A reconnect that lost the race against a user Disconnect must give up
// once it gets connectMu, not resurrect the tunnel.
func TestReconnectFnGivesUpAfterDisconnect(t *testing.T) {
	h, _ := newTestHelper(t)
	h.activeCfgs["vpn"] = &domain.WireGuardConfig{Name: "vpn"}
	h.autoReconnect["vpn"] = true

	h.connectMu.Lock() // a Disconnect in progress
	result := make(chan error, 1)
	go func() { result <- h.reconnectFn("vpn") }()
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-result:
		t.Fatalf("reconnectFn did not wait for connectMu: %v", err)
	default:
	}
	h.mu.Lock()
	delete(h.activeCfgs, "vpn")
	delete(h.autoReconnect, "vpn")
	h.mu.Unlock()
	h.connectMu.Unlock()

	if err := <-result; !errors.Is(err, reconnect.ErrGiveUp) {
		t.Fatalf("want ErrGiveUp, got %v", err)
	}
}

func TestReconnectFnGivesUpOnShutdown(t *testing.T) {
	h, _ := newTestHelper(t)
	h.activeCfgs["vpn"] = &domain.WireGuardConfig{Name: "vpn"}
	h.autoReconnect["vpn"] = true
	close(h.done)
	if err := h.reconnectFn("vpn"); !errors.Is(err, reconnect.ErrGiveUp) {
		t.Fatalf("want ErrGiveUp, got %v", err)
	}
}

// While a tunnel is held for reconnect, the kill switch stays loaded and
// passes only its cached endpoint (plus DNS when the endpoint is a name);
// releasing the last hold removes the rules.
func TestFirewallHoldKeepsKillSwitchDuringReconnect(t *testing.T) {
	h, fw := newTestHelper(t)
	h.policy = fwPolicy{killSwitch: true, dnsProtection: true}
	h.activeCfgs["vpn"] = &domain.WireGuardConfig{Name: "vpn", Peers: []domain.PeerConfig{{Endpoint: "vpn.example.com:51820"}}}
	h.fwEndpoints["vpn"] = cachedEndpoints{passes: []firewall.KillSwitchTunnel{{Proto: "udp", Endpoints: []string{"198.51.100.7:51820"}}}, hostname: true}

	if err := h.holdFirewall("vpn"); err != nil {
		t.Fatal(err)
	}
	// No port 53 pass for the whole hold: only around a lookup.
	want := firewall.Ruleset{
		KillSwitch:    true,
		DNSProtection: true,
		Tunnels:       []firewall.KillSwitchTunnel{{Proto: "udp", Endpoints: []string{"198.51.100.7:51820"}}},
	}
	if got := fw.last(); !reflect.DeepEqual(got, want) {
		t.Fatalf("held ruleset = %+v, want %+v", got, want)
	}

	if err := h.releaseFirewall("vpn"); err != nil {
		t.Fatal(err)
	}
	if got := fw.last(); !reflect.DeepEqual(got, firewall.Ruleset{}) {
		t.Fatalf("after release want empty ruleset, got %+v", got)
	}
	if _, ok := h.fwEndpoints["vpn"]; ok {
		t.Fatal("endpoint cache not pruned after release")
	}
}

// Enabling the policy with nothing connected records it without error and
// loads nothing.
func TestPolicyWithoutTunnelsIsRecorded(t *testing.T) {
	h, fw := newTestHelper(t)
	if _, err := h.handleSetKillSwitch([]byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	if !h.policy.killSwitch {
		t.Fatal("policy not recorded")
	}
	if got := fw.last(); !reflect.DeepEqual(got, firewall.Ruleset{}) {
		t.Fatalf("want empty ruleset with no tunnels, got %+v", got)
	}
}

// An OpenVPN error snapshot outlives the manager's removal of the tunnel,
// is never reported as active, and is cleared once the tunnel connects or
// the user disconnects it.
func TestOVPNErrorKeptInStatus(t *testing.T) {
	h, _ := newTestHelper(t)
	h.recordOVPNStatus(domain.ConnectionStatus{TunnelName: "work", State: domain.StateError, ErrorMessage: "AUTH_FAILED"})
	h.recordOVPNStatus(domain.ConnectionStatus{TunnelName: "work", State: domain.StateDisconnected})

	st := h.statusDTO()
	if st.State != domain.StateError || st.ErrorMessage != "AUTH_FAILED" ||
		len(st.Tunnels) != 1 || st.Tunnels[0].ErrorMessage != "AUTH_FAILED" {
		t.Fatalf("error not reported: %+v", st)
	}
	if len(st.ActiveTunnels) != 0 {
		t.Fatalf("error-only tunnel reported active: %v", st.ActiveTunnels)
	}
	h.recordOVPNStatus(domain.ConnectionStatus{TunnelName: "work", State: domain.StateConnected})
	if st := h.statusDTO(); st.State != "" || len(st.Tunnels) != 0 {
		t.Fatalf("error not cleared on connect: %+v", st)
	}

	h.recordOVPNStatus(domain.ConnectionStatus{TunnelName: "work", State: domain.StateError, ErrorMessage: "AUTH_FAILED"})
	if _, err := h.handleDisconnect([]byte(`{"tunnel_name":"work"}`)); err != nil {
		t.Fatal(err)
	}
	if st := h.statusDTO(); len(st.Tunnels) != 0 {
		t.Fatalf("disconnect did not clear the error: %+v", st)
	}
}

// A live OpenVPN entry is active unless it is in an error state.
func TestActiveTunnelsSkipLiveError(t *testing.T) {
	h, _ := newTestHelper(t)
	fo := &fakeOVPN{statuses: map[string]domain.ConnectionStatus{
		"a": {TunnelName: "a", State: domain.StateConnecting},
		"b": {TunnelName: "b", State: domain.StateError, ErrorMessage: "boom"},
	}}
	h.ovpnManager = fo
	if st := h.statusDTO(); !reflect.DeepEqual(st.ActiveTunnels, []string{"a"}) || len(st.Tunnels) != 2 {
		t.Fatalf("status = %+v", st)
	}
}

// fakeOVPN is a scriptable ovpnBackend.
type fakeOVPN struct {
	mu       sync.Mutex
	statuses map[string]domain.ConnectionStatus
	remotes  []ovpn.RemoteEndpoint
	awaiting bool
	polls    int
	onPoll   func(f *fakeOVPN, n int) // called under mu on each GetStatus

	connected []string
	recycled  []string
}

func (f *fakeOVPN) Connect(name string, _ []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connected = append(f.connected, name)
	return nil
}
func (f *fakeOVPN) Disconnect(string) error { return nil }
func (f *fakeOVPN) Recycle(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recycled = append(f.recycled, name)
	return nil
}
func (f *fakeOVPN) FeedCredentials(_, _, _, _ string) error { return nil }
func (f *fakeOVPN) SetOnDied(func(string))                  {}
func (f *fakeOVPN) Stop()                                   {}
func (f *fakeOVPN) IsAwaitingCredentials(string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.awaiting
}
func (f *fakeOVPN) ActiveRemotes() []ovpn.RemoteEndpoint {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.remotes)
}
func (f *fakeOVPN) ActiveTunnelNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Collect(maps.Keys(f.statuses))
}
func (f *fakeOVPN) AllStatuses() []domain.ConnectionStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Collect(maps.Values(f.statuses))
}
func (f *fakeOVPN) GetStatus(name string) *domain.ConnectionStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
	if f.onPoll != nil {
		f.onPoll(f, f.polls)
	}
	st, ok := f.statuses[name]
	if !ok {
		return nil
	}
	return &st
}

// A rejected password is not terminal: openvpn stays alive and re-prompts.
// waitOVPNConnected keeps waiting through the error state (and the prompt)
// until the tunnel connects.
func TestWaitOVPNConnectedSurvivesVerificationFailed(t *testing.T) {
	h, _ := newTestHelper(t)
	fo := &fakeOVPN{statuses: map[string]domain.ConnectionStatus{}}
	fo.onPoll = func(f *fakeOVPN, n int) {
		switch n {
		case 1:
			f.statuses["work"] = domain.ConnectionStatus{TunnelName: "work", State: domain.StateError, ErrorMessage: "Verification Failed: 'Auth'"}
		case 2:
			f.statuses["work"] = domain.ConnectionStatus{TunnelName: "work", State: domain.StateConnecting, ErrorMessage: "Verification Failed: 'Auth'"}
			f.awaiting = true
		case 4:
			f.awaiting = false
			f.statuses["work"] = domain.ConnectionStatus{TunnelName: "work", State: domain.StateConnected, InterfaceName: "utun7"}
			f.remotes = []ovpn.RemoteEndpoint{{TunnelName: "work", InterfaceName: "utun7", Proto: "udp", Addr: "203.0.113.5:1194"}}
		}
	}
	h.ovpnManager = fo
	if err := h.waitOVPNConnected("work"); err != nil {
		t.Fatalf("waitOVPNConnected: %v", err)
	}

	// The process exiting is terminal and reports the last error.
	fo2 := &fakeOVPN{statuses: map[string]domain.ConnectionStatus{}}
	fo2.onPoll = func(f *fakeOVPN, n int) {
		if n == 1 {
			f.statuses["work"] = domain.ConnectionStatus{TunnelName: "work", State: domain.StateError, ErrorMessage: "TLS handshake failed"}
		} else {
			delete(f.statuses, "work")
		}
	}
	h.ovpnManager = fo2
	if err := h.waitOVPNConnected("work"); err == nil || !strings.Contains(err.Error(), "TLS handshake failed") {
		t.Fatalf("want terminal error with message, got %v", err)
	}
}

// openvpn's own RECONNECTING (ping-restart) keeps the tunnel active: its
// interface and remote stay passed even though the state is Connecting.
func TestLiveTunnelsDuringOVPNReconnecting(t *testing.T) {
	h, fw := newTestHelper(t)
	h.policy = fwPolicy{killSwitch: true}
	h.ovpnManager = &fakeOVPN{
		statuses: map[string]domain.ConnectionStatus{"work": {TunnelName: "work", State: domain.StateConnecting, InterfaceName: "utun7", DNSServers: []string{"10.8.0.1"}}},
		remotes:  []ovpn.RemoteEndpoint{{TunnelName: "work", InterfaceName: "utun7", Proto: "udp", Addr: "203.0.113.5:1194"}},
	}
	if err := h.applyFirewall("policy"); err != nil {
		t.Fatal(err)
	}
	want := firewall.Ruleset{KillSwitch: true, DNSServers: []string{"10.8.0.1"},
		Tunnels: []firewall.KillSwitchTunnel{{InterfaceName: "utun7", Proto: "udp", Endpoints: []string{"203.0.113.5:1194"}}}}
	if got := fw.last(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ruleset = %+v, want %+v", got, want)
	}
}

// A failed apply leaves the old rules loaded, so the policy is reverted too.
func TestPolicyRevertedOnApplyFailure(t *testing.T) {
	h, fw := newTestHelper(t)
	fw.fail = true
	if _, err := h.handleSetKillSwitch([]byte(`{"enabled":true}`)); err == nil {
		t.Fatal("want error")
	}
	if _, err := h.handleSetDNSProtection([]byte(`{"enabled":true}`)); err == nil {
		t.Fatal("want error")
	}
	if h.policy != (fwPolicy{}) {
		t.Fatalf("policy not reverted: %+v", h.policy)
	}

	// Disabling also restores the blocks it would have released.
	fw.fail = false
	h.policy = fwPolicy{killSwitch: true}
	h.fwBlocked["vpn"] = domain.ProtocolWireGuard
	fw.fail = true
	if _, err := h.handleSetKillSwitch([]byte(`{"enabled":false}`)); err == nil {
		t.Fatal("want error")
	}
	if !h.policy.killSwitch || h.fwBlocked["vpn"] != domain.ProtocolWireGuard {
		t.Fatalf("revert lost state: policy=%+v blocked=%v", h.policy, h.fwBlocked)
	}
}

// Holds are counted: an older retry sequence's release (after
// triggerReconnectTunnel gave up waiting for it) must not end the newer
// sequence's hold.
func TestOverlappingHoldRelease(t *testing.T) {
	h, fw := newTestHelper(t)
	h.policy = fwPolicy{killSwitch: true}
	h.fwEndpoints["vpn"] = cachedEndpoints{passes: []firewall.KillSwitchTunnel{{Proto: "udp", Endpoints: []string{"198.51.100.7:51820"}}}}
	held := firewall.Ruleset{KillSwitch: true, Tunnels: []firewall.KillSwitchTunnel{{Proto: "udp", Endpoints: []string{"198.51.100.7:51820"}}}}

	_ = h.holdFirewall("vpn") // old sequence
	_ = h.holdFirewall("vpn") // new sequence
	_ = h.releaseFirewall("vpn")
	if got := fw.last(); !reflect.DeepEqual(got, held) {
		t.Fatalf("old release dropped the new hold: %+v", got)
	}
	_ = h.releaseFirewall("vpn")
	if got := fw.last(); !reflect.DeepEqual(got, firewall.Ruleset{}) {
		t.Fatalf("after last release want empty, got %+v", got)
	}
}

// Fail closed: a tunnel that dies without auto-reconnect under the kill
// switch stays blocked (and shown as such) until the user disconnects it;
// turning the kill switch off or a retry sequence ending also behave.
func TestDeadTunnelBlockedUntilUserActs(t *testing.T) {
	h, fw := newTestHelper(t)
	h.monitor = reconnect.NewMonitor(h.manager, nil, nil, reconnect.DefaultConfig())
	h.policy = fwPolicy{killSwitch: true, dnsProtection: true}
	h.activeCfgs["vpn"] = &domain.WireGuardConfig{Name: "vpn"}

	h.onWireGuardEngineDied("vpn")
	block := firewall.Ruleset{KillSwitch: true, DNSProtection: true}
	if got := fw.last(); !reflect.DeepEqual(got, block) {
		t.Fatalf("dead tunnel not blocked: %+v", got)
	}
	st := h.statusDTO()
	if len(st.Tunnels) != 1 || !st.Tunnels[0].KillSwitchBlocked || st.Tunnels[0].State != domain.StateError ||
		st.Tunnels[0].Protocol != domain.ProtocolWireGuard || len(st.ActiveTunnels) != 0 {
		t.Fatalf("blocked state not surfaced: %+v", st)
	}
	if _, active := h.anyTunnelActive(); !active {
		t.Fatal("helper would exit (and flush the block) while a tunnel is blocked")
	}

	// Policy pushes keep the block.
	if _, err := h.handleSetDNSProtection([]byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	if got := fw.last(); !reflect.DeepEqual(got, block) {
		t.Fatalf("policy push dropped the block: %+v", got)
	}

	// The user disconnecting the dead tunnel always clears it.
	if _, err := h.handleDisconnect([]byte(`{"tunnel_name":"vpn"}`)); err != nil {
		t.Fatal(err)
	}
	if got := fw.last(); !reflect.DeepEqual(got, firewall.Ruleset{}) {
		t.Fatalf("disconnect did not clear the block: %+v", got)
	}
	if st := h.statusDTO(); len(st.Tunnels) != 0 {
		t.Fatalf("status still shows the tunnel: %+v", st)
	}

	// Turning the kill switch off clears it too.
	h.fwBlocked["vpn"] = domain.ProtocolWireGuard
	if _, err := h.handleSetKillSwitch([]byte(`{"enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	if got := fw.last(); !reflect.DeepEqual(got, firewall.Ruleset{}) || len(h.fwBlocked) != 0 {
		t.Fatalf("kill switch off did not clear the block: %+v %v", got, h.fwBlocked)
	}

	// Without the kill switch a death just drops the tunnel.
	h.activeCfgs["vpn"] = &domain.WireGuardConfig{Name: "vpn"}
	h.onWireGuardEngineDied("vpn")
	if len(h.fwBlocked) != 0 {
		t.Fatal("blocked without kill switch")
	}

	// A retry sequence that ends without the tunnel (still wanted) blocks.
	h.policy.killSwitch = true
	h.autoReconnect["vpn"] = true
	_ = h.holdFirewall("vpn")
	_ = h.releaseFirewall("vpn")
	if _, ok := h.fwBlocked["vpn"]; !ok {
		t.Fatal("give-up did not block")
	}
	if got := fw.last(); !reflect.DeepEqual(got, firewall.Ruleset{KillSwitch: true, DNSProtection: true}) {
		t.Fatalf("give-up ruleset = %+v", got)
	}
	// A new sequence lifts the block for its own endpoint passes.
	_ = h.holdFirewall("vpn")
	if _, ok := h.fwBlocked["vpn"]; ok {
		t.Fatal("hold did not lift the block")
	}
}

// The reconnect lookup opens port 53 to the system resolvers only, and only
// while resolving; every configured remote of a multi-remote profile is
// passed during the hold.
func TestReconnectLookupWindow(t *testing.T) {
	h, fw := newTestHelper(t)
	h.policy = fwPolicy{killSwitch: true}
	h.activeOVPNCfgs["work"] = []byte("client\nproto udp\nremote vpn1.example.com 1194\nremote 198.51.100.9 443 tcp\n<connection>\nremote vpn2.example.com\nproto tcp\n</connection>\n")
	h.fwHeld["work"] = 1

	oldRes, oldLookup := systemResolvers, resolveHost
	defer func() { systemResolvers, resolveHost = oldRes, oldLookup }()
	systemResolvers = func() []string { return []string{"192.168.1.1"} }
	var during firewall.Ruleset
	resolveHost = func(_ context.Context, host string) ([]string, error) {
		during = fw.last()
		return map[string][]string{"vpn1.example.com": {"203.0.113.1"}, "vpn2.example.com": {"203.0.113.2"}}[host], nil
	}

	h.passResolvedHostnames("work")
	if !reflect.DeepEqual(during.DNSLookupServers, []string{"192.168.1.1"}) {
		t.Fatalf("lookup window not open while resolving: %+v", during)
	}
	got := fw.last()
	if len(got.DNSLookupServers) != 0 {
		t.Fatalf("lookup window left open: %+v", got)
	}
	var passed []string
	for _, tn := range got.Tunnels {
		for _, ep := range tn.Endpoints {
			passed = append(passed, tn.Proto+" "+ep)
		}
	}
	slices.Sort(passed)
	want := []string{"tcp 198.51.100.9:443", "tcp 203.0.113.2:1194", "udp 203.0.113.1:1194"}
	if !reflect.DeepEqual(passed, want) {
		t.Fatalf("passed %v, want %v", passed, want)
	}
}
