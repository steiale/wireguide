package helper

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/firewall"
	"github.com/steiale/wireguide/internal/reconnect"
	"github.com/steiale/wireguide/internal/tunnel"
)

type fakeFirewall struct {
	mu      sync.Mutex
	applied []firewall.Ruleset
}

func (f *fakeFirewall) Apply(rs firewall.Ruleset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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
		fwHeld:         map[string]bool{},
		fwEndpoints:    map[string]cachedEndpoints{},
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
	h.fwEndpoints["vpn"] = cachedEndpoints{proto: "udp", endpoints: []string{"198.51.100.7:51820"}, hostname: true}

	if err := h.holdFirewall("vpn"); err != nil {
		t.Fatal(err)
	}
	want := firewall.Ruleset{
		KillSwitch:     true,
		DNSProtection:  true,
		AllowDNSLookup: true,
		Tunnels:        []firewall.KillSwitchTunnel{{Proto: "udp", Endpoints: []string{"198.51.100.7:51820"}}},
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

// An OpenVPN error snapshot outlives the manager's removal of the tunnel
// and is cleared once the tunnel connects.
func TestOVPNErrorKeptInStatus(t *testing.T) {
	h, _ := newTestHelper(t)
	h.recordOVPNStatus(domain.ConnectionStatus{TunnelName: "work", State: domain.StateError, ErrorMessage: "AUTH_FAILED"})
	h.recordOVPNStatus(domain.ConnectionStatus{TunnelName: "work", State: domain.StateDisconnected})

	st := h.statusDTO()
	if st.State != domain.StateError || st.ErrorMessage != "AUTH_FAILED" ||
		len(st.Tunnels) != 1 || st.Tunnels[0].ErrorMessage != "AUTH_FAILED" {
		t.Fatalf("error not reported: %+v", st)
	}
	h.recordOVPNStatus(domain.ConnectionStatus{TunnelName: "work", State: domain.StateConnected})
	if st := h.statusDTO(); st.State != "" || len(st.Tunnels) != 0 {
		t.Fatalf("error not cleared on connect: %+v", st)
	}
}
