package ovpn

import (
	"encoding/base64"
	"net"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/steiale/wireguide/internal/domain"
)

type managerSpy struct {
	mu       sync.Mutex
	active   []bool
	died     []string
	statuses []domain.ConnectionStatus
}

func newTestManager(t *testing.T) (*Manager, *managerSpy) {
	spy := &managerSpy{}
	m := &Manager{
		tunnels:    map[string]*entry{},
		runtimeDir: t.TempDir(),
		onStatus: func(s domain.ConnectionStatus) {
			spy.mu.Lock()
			spy.statuses = append(spy.statuses, s)
			spy.mu.Unlock()
		},
		onActiveChange: func(_ string, a bool) {
			spy.mu.Lock()
			spy.active = append(spy.active, a)
			spy.mu.Unlock()
		},
	}
	m.onDied = func(n string) {
		spy.mu.Lock()
		spy.died = append(spy.died, n)
		spy.mu.Unlock()
	}
	return m, spy
}

func addEntry(m *Manager, name string) *entry {
	e := newEntry(name, &profile{verb: -1})
	m.tunnels[name] = e
	return e
}

func TestActiveSurvivesReconnecting(t *testing.T) {
	m, spy := newTestManager(t)
	e := addEntry(m, "t")
	e.status.InterfaceName = "utun7"
	m.onMgmtState("t", "CONNECTED", "10.8.0.2", "203.0.113.5:1194")
	m.onMgmtState("t", "RECONNECTING", "", "")
	if e.status.State != domain.StateConnecting {
		t.Fatalf("state %s", e.status.State)
	}
	if r := m.ActiveRemotes(); len(r) != 1 || r[0].Addr != "203.0.113.5:1194" {
		t.Errorf("reconnecting tunnel dropped from ActiveRemotes: %+v", r)
	}
	// A crash while reconnecting is still an unexpected death, reported
	// through onDied alone (the helper holds or blocks it in one apply).
	m.cleanup("t")
	if len(spy.died) != 1 {
		t.Errorf("onDied not fired: %v", spy.died)
	}
	if len(spy.active) != 1 || !spy.active[0] {
		t.Errorf("onActiveChange = %v, want [true]", spy.active)
	}
}

func TestUserDisconnectWhileReconnecting(t *testing.T) {
	m, spy := newTestManager(t)
	e := addEntry(m, "t")
	m.onMgmtState("t", "CONNECTED", "", "")
	m.onMgmtState("t", "RECONNECTING", "", "")
	m.onMgmtState("t", "CONNECTED", "", "") // reconnect re-announces
	m.onMgmtState("t", "RECONNECTING", "", "")
	e.userInitiated = true
	m.cleanup("t")
	if len(spy.died) != 0 {
		t.Errorf("onDied fired for user disconnect")
	}
	if n := len(spy.active); n != 3 || spy.active[n-1] {
		t.Errorf("onActiveChange = %v, want [true true false]", spy.active)
	}
}

func TestNeverActiveNoCallbacks(t *testing.T) {
	m, spy := newTestManager(t)
	addEntry(m, "t")
	m.onMgmtState("t", "AUTH", "", "")
	m.cleanup("t")
	if len(spy.active) != 0 || len(spy.died) != 0 {
		t.Errorf("active=%v died=%v", spy.active, spy.died)
	}
}

func TestErrorIsSticky(t *testing.T) {
	m, spy := newTestManager(t)
	addEntry(m, "t")
	m.fail("t", "Cannot open TUN/TAP dev", false)
	m.onMgmtState("t", "RECONNECTING", "", "")
	if s := m.GetStatus("t"); s.State != domain.StateError || s.ErrorMessage == "" {
		t.Errorf("error overwritten: %+v", s)
	}
	m.cleanup("t")
	final := spy.statuses[len(spy.statuses)-1]
	if final.State != domain.StateError || final.ErrorMessage != "Cannot open TUN/TAP dev" {
		t.Errorf("final snapshot = %+v", final)
	}
}

// A rejected password is followed by a re-prompt: the state stays
// Connecting (the GUI keeps its auth modal open) and the text is carried as
// the error message for the re-prompt to show.
func TestAuthFailedIsNotTerminal(t *testing.T) {
	m, _ := newTestManager(t)
	e := addEntry(m, "t")
	m.onMgmtAuthFailed("t", "Verification Failed: 'Auth'")
	m.onMgmtState("t", "RECONNECTING", "", "")
	m.onMgmtState("t", "WAIT", "", "")
	if s := m.GetStatus("t"); s.State != domain.StateConnecting || s.ErrorMessage != "Verification Failed: 'Auth'" {
		t.Fatalf("after auth failure: %+v", s)
	}

	// A prompt clears an earlier error state, keeping the text.
	m.fail("t", "sending credentials failed: broken pipe", false)
	done := make(chan struct{})
	go func() { m.onMgmtAuthPrompt("t", e, nil); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for !m.IsAwaitingCredentials("t") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s := m.GetStatus("t"); s.State != domain.StateConnecting || s.ErrorMessage == "" {
		t.Fatalf("prompt left error state: %+v", s)
	}
	e.closeOnce.Do(func() { close(e.closeCh) })
	<-done
}

// A terminal failure of an active tunnel (e.g. the credential prompt timed
// out during a reconnect) is a death, not a user disconnect, so the kill
// switch and auto-reconnect still react.
func TestTerminalFailureOfActiveTunnelIsDeath(t *testing.T) {
	m, spy := newTestManager(t)
	e := addEntry(m, "t")
	m.onMgmtState("t", "CONNECTED", "", "203.0.113.5:1194")
	m.fail("t", "timed out waiting for credentials", true)
	if e.userInitiated {
		t.Fatal("terminal failure marked as user-initiated")
	}
	m.cleanup("t")
	if len(spy.died) != 1 {
		t.Fatalf("onDied = %v, want one death", spy.died)
	}
}

// The utun name can arrive after CONNECTED; an active tunnel then gets
// onActiveChange(true) again so the firewall passes it.
func TestInterfaceAfterConnectedReapplies(t *testing.T) {
	m, spy := newTestManager(t)
	addEntry(m, "t")
	m.onMgmtState("t", "CONNECTED", "", "203.0.113.5:1194")
	if r := m.ActiveRemotes(); len(r) != 0 {
		t.Fatalf("remote listed without interface: %+v", r)
	}
	m.setInterface("t", "utun9")
	m.setInterface("t", "utun9") // only the first sighting re-applies
	if len(spy.active) != 2 || !spy.active[1] {
		t.Fatalf("onActiveChange = %v, want [true true]", spy.active)
	}
	if r := m.ActiveRemotes(); len(r) != 1 || r[0].InterfaceName != "utun9" {
		t.Fatalf("ActiveRemotes = %+v", r)
	}
}

// Stop waits for each tunnel's teardown before returning. Asserted on what
// cleanup itself does (entry removed, runtime files gone, final status
// emitted), all of which happens before it closes e.done.
func TestStopWaitsForCleanup(t *testing.T) {
	m, spy := newTestManager(t)
	addEntry(m, "t")
	for _, p := range []string{m.configPath("t"), m.sockPath("t"), m.pidPath("t")} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		m.cleanup("t")
	}()
	start := time.Now()
	m.Stop()
	if m.GetStatus("t") != nil {
		t.Fatalf("Stop returned after %v with the entry still present", time.Since(start))
	}
	for _, p := range []string{m.configPath("t"), m.sockPath("t"), m.pidPath("t")} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("Stop returned before cleanup removed %s", p)
		}
	}
	spy.mu.Lock()
	defer spy.mu.Unlock()
	if n := len(spy.statuses); n == 0 || spy.statuses[n-1].State != domain.StateDisconnected {
		t.Fatalf("final status not emitted before Stop returned: %+v", spy.statuses)
	}
}

// --persist-remote-ip only for a single-remote profile (after <connection>
// expansion): openvpn's persist-remote-ip is broken with multiple remotes.
func TestArgsPersistRemoteIP(t *testing.T) {
	m, _ := newTestManager(t)
	for _, tc := range []struct {
		profile string
		want    bool
	}{
		{"client\nremote a.example 1194\n", true},
		{"client\n<connection>\nremote a.example\n</connection>\n", true},
		{"client\nremote a.example\nremote b.example\n", false},
		{"client\nremote 192.0.2.1\n<connection>\nremote b.example\n</connection>\n", false},
	} {
		p, err := inspectProfile([]byte(tc.profile))
		if err != nil {
			t.Fatalf("%q: %v", tc.profile, err)
		}
		args := m.args("c", "s", p)
		if slices.Contains(args, "--persist-remote-ip") != tc.want || !slices.Contains(args, "--persist-tun") {
			t.Errorf("%q: args = %v, want persist-remote-ip=%v", tc.profile, args, tc.want)
		}
	}
}

// Recycle is not a user disconnect: an active tunnel it stops is a death.
func TestRecycleIsDeath(t *testing.T) {
	m, spy := newTestManager(t)
	e := addEntry(m, "t")
	m.onMgmtState("t", "CONNECTED", "", "203.0.113.5:1194")
	m.onMgmtState("t", "RECONNECTING", "", "")
	if err := m.Recycle("t"); err != nil {
		t.Fatal(err)
	}
	if e.userInitiated {
		t.Fatal("recycle marked as user-initiated")
	}
	m.cleanup("t")
	if len(spy.died) != 1 {
		t.Fatalf("onDied = %v, want one death", spy.died)
	}
}

func TestCollectRemotes(t *testing.T) {
	cfg, err := ParseOVPN([]byte("client\nport 1195\nproto tcp-client\nremote a.example\nremote 2001:db8::1 443 udp\n<connection>\nremote b.example 8443\nproto udp6\n</connection>\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []RemoteSpec{
		{Host: "a.example", Port: "1195", Proto: "tcp"},
		{Host: "2001:db8::1", Port: "443", Proto: "udp"},
		{Host: "b.example", Port: "8443", Proto: "udp"},
	}
	if !slices.Equal(cfg.Remotes, want) {
		t.Fatalf("Remotes = %+v, want %+v", cfg.Remotes, want)
	}
	if cfg.Remote != "a.example" {
		t.Errorf("Remote = %q", cfg.Remote)
	}
}

func TestCRV1UsesChallengeUsername(t *testing.T) {
	m, _ := newTestManager(t)
	e := addEntry(m, "t")
	a, b := net.Pipe()
	defer a.Close()
	e.mgmt = newMgmtClient(b)
	e.lastUsername = "stale"
	got := make(chan string, 2)
	go func() {
		buf := make([]byte, 512)
		for i := 0; i < 2; i++ {
			n, _ := a.Read(buf)
			got <- string(buf[:n])
		}
	}()
	ch := parseDynamicChallenge("Verification Failed: 'Auth' ['CRV1:R:sid:" + base64.StdEncoding.EncodeToString([]byte("bob")) + ":Token']")
	m.onMgmtDynamicChallenge("t", e, ch)
	e.authCh <- authReply{response: "123456"}
	m.onMgmtAuthPrompt("t", e, nil)
	for _, want := range []string{"username \"Auth\" \"bob\"\n", "password \"Auth\" \"CRV1::sid::123456\"\n"} {
		select {
		case g := <-got:
			if g != want {
				t.Errorf("got %q, want %q", g, want)
			}
		case <-time.After(time.Second):
			t.Fatal("credentials not sent")
		}
	}
}

// onDying runs before the dying entry is removed, while ActiveRemotes still
// passes it, and before the final status and onDied; a user teardown gets
// neither.
func TestOnDyingBeforeRemoval(t *testing.T) {
	m, spy := newTestManager(t)
	var order []string
	m.onDying = func(n string) {
		spy.mu.Lock()
		defer spy.mu.Unlock()
		if m.GetStatus(n) == nil || len(m.ActiveRemotes()) != 1 || len(spy.died) != 0 {
			t.Errorf("onDying ran after removal: status=%v remotes=%v died=%v", m.GetStatus(n), m.ActiveRemotes(), spy.died)
		}
		order = append(order, "dying")
	}
	e := addEntry(m, "t")
	e.status.InterfaceName = "utun7"
	m.onMgmtState("t", "CONNECTED", "", "203.0.113.5:1194")
	m.cleanup("t")
	if !slices.Equal(order, []string{"dying"}) || len(spy.died) != 1 {
		t.Fatalf("order=%v died=%v", order, spy.died)
	}

	order = nil
	e = addEntry(m, "u")
	m.onMgmtState("u", "CONNECTED", "", "203.0.113.5:1194")
	e.userInitiated = true
	m.cleanup("u")
	if len(order) != 0 {
		t.Fatalf("onDying fired for a user disconnect")
	}
}
