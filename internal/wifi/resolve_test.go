package wifi

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSource builds an ssidSource whose subprocess runner answers from a
// table keyed by the joined command line and records every call.
func fakeSource(auth AuthStatus, info coreWLANInfo, outputs map[string]string, calls *[]string) ssidSource {
	return ssidSource{
		auth: func() AuthStatus { return auth },
		wlan: func() coreWLANInfo { return info },
		run: func(name string, args ...string) string {
			cmd := strings.Join(append([]string{name}, args...), " ")
			*calls = append(*calls, cmd)
			return outputs[cmd]
		},
	}
}

const (
	cmdPorts   = "/usr/sbin/networksetup -listallhardwareports"
	cmdSummary = "/usr/sbin/ipconfig getsummary en0"
	cmdAirport = "/usr/sbin/networksetup -getairportnetwork en0"
)

func TestResolve(t *testing.T) {
	assoc := coreWLANInfo{HasInterface: true, Associated: true, Interface: "en0"}
	withSSID := assoc
	withSSID.SSID = "Office"
	idle := coreWLANInfo{HasInterface: true, Interface: "en0"}

	cases := []struct {
		name      string
		auth      AuthStatus
		info      coreWLANInfo
		outputs   map[string]string
		want      string
		wantCalls int
	}{
		{"corewlan authorized", AuthAuthorized, withSSID, nil, "Office", 0},
		{"corewlan ssid with spaces kept verbatim", AuthAuthorized, coreWLANInfo{HasInterface: true, Associated: true, SSID: " Cafe "}, nil, " Cafe ", 0},
		{"no wifi hardware", AuthDenied, coreWLANInfo{}, nil, "", 0},
		{"authorized, not associated: no subprocess", AuthAuthorized, idle, nil, "", 0},
		{"denied, redacted everywhere", AuthDenied, assoc, map[string]string{
			cmdSummary: "  SSID : <redacted>\n",
			cmdAirport: "Current Wi-Fi Network: <redacted>\n",
		}, "", 2},
		{"denied, ipconfig still reveals ssid (older macOS)", AuthDenied, assoc, map[string]string{
			cmdSummary: "<dictionary> {\n  SSID : Home\n}\n",
		}, "Home", 1},
		{"notDetermined, networksetup fallback", AuthNotDetermined, assoc, map[string]string{
			cmdSummary: "ipconfig: getsummary en0 failed\n",
			cmdAirport: "Current Wi-Fi Network: Home\n",
		}, "Home", 2},
		{"denied, error text ignored", AuthDenied, assoc, map[string]string{
			cmdAirport: "You are not associated with an AirPort network.\n",
		}, "", 2},
		{"authorized but corewlan nil while associated: fallback", AuthAuthorized, assoc, map[string]string{
			cmdSummary: "  SSID : Lab\n",
		}, "Lab", 1},
		{"corewlan redacted placeholder rejected", AuthDenied, coreWLANInfo{HasInterface: true, Associated: true, Interface: "en0", SSID: "<redacted>"}, nil, "", 2},
		{"no interface name: discover via hardware ports", AuthDenied, coreWLANInfo{HasInterface: true, Associated: true}, map[string]string{
			cmdPorts:   "Hardware Port: Wi-Fi\nDevice: en0\n",
			cmdSummary: "  SSID : Home\n",
		}, "Home", 2},
		{"no interface name and none found", AuthDenied, coreWLANInfo{HasInterface: true, Associated: true}, nil, "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			got := fakeSource(tc.auth, tc.info, tc.outputs, &calls).resolve()
			if got != tc.want {
				t.Errorf("resolve() = %q, want %q", got, tc.want)
			}
			if len(calls) != tc.wantCalls {
				t.Errorf("subprocess calls = %v, want %d", calls, tc.wantCalls)
			}
		})
	}
}

func TestParseAirportNetwork(t *testing.T) {
	cases := map[string]string{
		"Current Wi-Fi Network: Home Net\n":                 "Home Net",
		"Current AirPort Network: Legacy\n":                 "Legacy",
		"Current Wi-Fi Network: <redacted>\n":               "",
		"You are not associated with an AirPort network.\n": "",
		"Wi-Fi power is currently off.\n":                   "",
		"** Error: Error obtaining wireless information.\n": "",
		"en9 is not a Wi-Fi interface.\n":                   "",
		"":                                                  "",
	}
	for in, want := range cases {
		if got := parseAirportNetwork(in); got != want {
			t.Errorf("parseAirportNetwork(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanSSID(t *testing.T) {
	cases := map[string]string{
		"Home":                                 "Home",
		"<redacted>":                           "",
		"<REDACTED>":                           "",
		"   ":                                  "",
		"":                                     "",
		strings.Repeat("x", 32):                strings.Repeat("x", 32),
		strings.Repeat("x", 33):                "",
		"Error obtaining wireless information": "",
	}
	for in, want := range cases {
		if got := cleanSSID(in); got != want {
			t.Errorf("cleanSSID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMonitorRecheck verifies an auth-change Recheck makes the monitor read
// the SSID immediately (well before the 5 s tick) and fire onChanged when it
// went from "" (unauthorized) to a real name.
func TestMonitorRecheck(t *testing.T) {
	var ssid atomic.Value
	ssid.Store("")
	changed := make(chan [2]string, 4)
	m := NewMonitor(DefaultRules(), func(o, n string) { changed <- [2]string{o, n} })
	m.readSSID = func() string { return ssid.Load().(string) }
	m.Start()
	defer m.Stop()

	time.Sleep(50 * time.Millisecond) // let the initial read happen
	ssid.Store("Home")
	m.Recheck()
	select {
	case got := <-changed:
		if got != [2]string{"", "Home"} {
			t.Fatalf("onChanged(%q, %q), want (\"\", \"Home\")", got[0], got[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recheck did not trigger an immediate SSID read")
	}
	m.Recheck()
	m.Recheck() // coalesced, must not block
}

func TestHasActiveRules(t *testing.T) {
	cases := []struct {
		r    *Rules
		want bool
	}{
		{nil, false},
		{DefaultRules(), false},
		{&Rules{Enabled: true}, false},
		{&Rules{Enabled: false, TrustedSSIDs: []string{"a"}}, false},
		{&Rules{Enabled: true, TrustedSSIDs: []string{"a"}}, true},
		{&Rules{Enabled: true, SSIDTunnelMap: map[string]string{"a": "t"}}, true},
		{&Rules{Enabled: true, AutoConnectUntrusted: true}, false},
		{&Rules{Enabled: true, AutoConnectUntrusted: true, DefaultTunnel: "t"}, true},
	}
	for i, tc := range cases {
		if got := tc.r.HasActiveRules(); got != tc.want {
			t.Errorf("case %d: HasActiveRules() = %v, want %v", i, got, tc.want)
		}
	}
}
