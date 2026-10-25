package firewall

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestBuildRulesGolden(t *testing.T) {
	wg1 := KillSwitchTunnel{InterfaceName: "utun4", Proto: "udp", Endpoints: []string{"198.51.100.7:51820", "[2001:db8::7]:51820"}}
	wg2 := KillSwitchTunnel{InterfaceName: "utun6", Endpoints: []string{"203.0.113.9:51821"}}
	ovpn := KillSwitchTunnel{InterfaceName: "utun7", Proto: "tcp-client", Endpoints: []string{"192.0.2.10:443"}}

	cases := []struct {
		name string
		rs   Ruleset
	}{
		{"killswitch_single", Ruleset{KillSwitch: true, Tunnels: []KillSwitchTunnel{wg1}}},
		{"killswitch_multi", Ruleset{KillSwitch: true, Tunnels: []KillSwitchTunnel{wg1, wg2, ovpn}}},
		{"dns_only", Ruleset{DNSProtection: true, DNSServers: []string{"10.0.0.1", "fd00::1"}, Tunnels: []KillSwitchTunnel{wg1, wg2}}},
		{"killswitch_dns", Ruleset{KillSwitch: true, DNSProtection: true, DNSServers: []string{"10.0.0.1"}, Tunnels: []KillSwitchTunnel{wg1, ovpn}}},
		// wg2 reconnecting by hostname: endpoint-only pass plus DNS lookups.
		{"suspend_hostname", Ruleset{KillSwitch: true, DNSProtection: true, DNSServers: []string{"10.0.0.1"}, DNSLookupServers: []string{"192.168.1.1", "fe80::1"},
			Tunnels: []KillSwitchTunnel{wg1, {Proto: "udp", Endpoints: []string{"203.0.113.9:51821"}}}}},
		{"suspend_only_dns", Ruleset{DNSProtection: true, Tunnels: []KillSwitchTunnel{{Endpoints: []string{"203.0.113.9:51821"}}}}},
		// A dead tunnel under the kill switch: nothing passed but loopback,
		// DHCP and neighbour discovery.
		{"blocked_dead_tunnel", Ruleset{KillSwitch: true, DNSProtection: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildRules(tc.rs)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", tc.name+".golden")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			if got != string(want) {
				t.Errorf("rules mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
			}
		})
	}
}

func TestBuildRulesEmpty(t *testing.T) {
	for name, rs := range map[string]Ruleset{
		"nothing":              {},
		"dns_pending":          {DNSProtection: true, Tunnels: []KillSwitchTunnel{{InterfaceName: "utun4"}}},
		"tunnels_no_policy":    {Tunnels: []KillSwitchTunnel{{InterfaceName: "utun4"}}},
		"lookup_without_rules": {DNSLookupServers: []string{"192.168.1.1"}},
	} {
		got, err := BuildRules(rs)
		if err != nil || got != "" {
			t.Errorf("%s: got %q, %v; want empty", name, got, err)
		}
	}
}

func TestBuildRulesRejectsInjection(t *testing.T) {
	for name, rs := range map[string]Ruleset{
		"iface":    {KillSwitch: true, Tunnels: []KillSwitchTunnel{{InterfaceName: "utun4 all\npass"}}},
		"endpoint": {KillSwitch: true, Tunnels: []KillSwitchTunnel{{InterfaceName: "utun4", Endpoints: []string{"evil\npass all:1"}}}},
		"port":     {KillSwitch: true, Tunnels: []KillSwitchTunnel{{InterfaceName: "utun4", Endpoints: []string{"1.2.3.4:1\npass all"}}}},
		"dns":      {DNSProtection: true, DNSServers: []string{"any"}, Tunnels: []KillSwitchTunnel{{InterfaceName: "utun4"}}},
		"lookup":   {KillSwitch: true, DNSLookupServers: []string{"any port 53\npass all"}},
	} {
		if _, err := BuildRules(rs); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// The reconnect lookup window never opens port 53 to any host.
func TestDNSLookupNeverToAny(t *testing.T) {
	got, err := BuildRules(Ruleset{KillSwitch: true, DNSProtection: true, DNSLookupServers: []string{"192.168.1.1"},
		Tunnels: []KillSwitchTunnel{{Proto: "udp", Endpoints: []string{"203.0.113.9:51821"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "to any port 53 flags any") || !strings.Contains(got, "to 192.168.1.1 port 53") {
		t.Fatalf("lookup pass not restricted to the resolver:\n%s", got)
	}
}
