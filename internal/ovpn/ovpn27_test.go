package ovpn

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const pushPrefix = "2026-10-25 10:00:00 PUSH: Received control message: '"

// pushedEntries is what Connect applies for one complete PUSH_REPLY.
func pushedEntries(t *testing.T, profileBody, line string) []string {
	t.Helper()
	p, err := inspectProfile([]byte(vbase + profileBody))
	if err != nil {
		t.Fatal(err)
	}
	msg, ok := parsePushLine(line, p.pullFilters)
	if !ok {
		t.Fatalf("not a push line: %q", line)
	}
	if msg.rejected {
		return nil
	}
	return p.dns.merge(msg.dns).entries()
}

func TestPushedDNS(t *testing.T) {
	cases := []struct {
		name, profile, line string
		want                []string
	}{
		{
			"dhcp-option", "",
			pushPrefix + "PUSH_REPLY,dhcp-option DNS 192.168.1.11,dhcp-option DOMAIN corp.local,ifconfig 10.8.0.2 255.255.255.0'",
			[]string{"192.168.1.11", "corp.local"},
		},
		{
			"DNS6 and DOMAIN-SEARCH, last option", "",
			pushPrefix + "PUSH_REPLY,dhcp-option DNS6 fd00::1,dhcp-option DOMAIN-SEARCH a.example'",
			[]string{"fd00::1", "a.example"},
		},
		{
			"dns server wins over dhcp-option", "",
			pushPrefix + "PUSH_REPLY,dhcp-option DNS 1.1.1.1,dns server 0 address 10.8.0.1 10.8.0.2:5353 [fd00::1]:53 fd00::2,dns search-domains corp.example b.example,route-gateway 10.8.0.1'",
			[]string{"10.8.0.1", "10.8.0.2", "fd00::1", "fd00::2", "corp.example", "b.example"},
		},
		{
			"no dns", "",
			pushPrefix + "PUSH_REPLY,route-gateway 10.8.0.1,dns server 0 resolve-domains x.example'",
			nil,
		},
		{
			"profile dhcp-option merged before pushed", "dhcp-option DNS 9.9.9.9\n",
			pushPrefix + "PUSH_REPLY,dhcp-option DNS 10.8.0.1'",
			[]string{"9.9.9.9", "10.8.0.1"},
		},
		{
			"profile only", "dns server 1 address 9.9.9.9\n",
			pushPrefix + "PUSH_REPLY,route-gateway 10.8.0.1'",
			[]string{"9.9.9.9"},
		},
		{
			"pushed priority replaces profile's", "dns server 0 address 9.9.9.9\ndns server 5 address 8.8.8.8\n",
			pushPrefix + "PUSH_REPLY,dns server 0 address 10.8.0.1'",
			[]string{"10.8.0.1", "8.8.8.8"},
		},
		{
			"pull-filter ignore dhcp-option", "pull-filter ignore \"dhcp-option\"\ndhcp-option DNS 9.9.9.9\n",
			pushPrefix + "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.local'",
			[]string{"9.9.9.9"},
		},
		{
			"pull-filter prefix is exact", "pull-filter ignore \"dhcp-option DNS\"\n",
			pushPrefix + "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.local'",
			[]string{"corp.local"},
		},
		{
			"first matching filter wins", "pull-filter accept \"dhcp-option DNS 10.\"\npull-filter ignore \"dhcp-option\"\n",
			pushPrefix + "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS 1.1.1.1'",
			[]string{"10.8.0.1"},
		},
		{
			"pull-filter ignore dns", "pull-filter ignore dns\n",
			pushPrefix + "PUSH_REPLY,dns server 0 address 10.8.0.1,dhcp-option DNS 1.1.1.1'",
			[]string{"1.1.1.1"},
		},
		{
			"pull-filter reject drops the push", "pull-filter reject \"dhcp-option DNS 6.6.6.6\"\n",
			pushPrefix + "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS 6.6.6.6'",
			nil,
		},
	}
	for _, c := range cases {
		if got := pushedEntries(t, c.profile, c.line); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParsePushLineUpdateAndContinuation(t *testing.T) {
	msg, ok := parsePushLine(pushPrefix+"PUSH_UPDATE,-dns,?dns server 1 address 10.9.0.1'", nil)
	if !ok || !msg.update || !msg.dns.touched || !reflect.DeepEqual(msg.dns.entries(), []string{"10.9.0.1"}) {
		t.Errorf("update: %+v ok=%v", msg, ok)
	}
	msg, _ = parsePushLine(pushPrefix+"PUSH_UPDATE,route 10.0.0.0 255.0.0.0'", nil)
	if msg.dns.touched {
		t.Error("update without DNS should not touch DNS")
	}
	msg, _ = parsePushLine(pushPrefix+"PUSH_REPLY,dhcp-option DNS 10.8.0.1,push-continuation 2'", nil)
	if !msg.more {
		t.Error("push-continuation 2 not detected")
	}
	if _, ok := parsePushLine("AUTH: Received control message: 'AUTH_FAILED'", nil); ok {
		t.Error("non-push line accepted")
	}
	// Truncated log line (no closing quote).
	msg, ok = parsePushLine(pushPrefix+"PUSH_REPLY,dhcp-option DNS 10.8.0.1", nil)
	if !ok || !reflect.DeepEqual(msg.dns.entries(), []string{"10.8.0.1"}) {
		t.Errorf("truncated: %+v", msg)
	}
}

func TestValidateOVPNDNSUpdown(t *testing.T) {
	base := "client\nremote vpn.example.com 1194\n"
	if err := ValidateOVPN([]byte(base + "dns-updown disable\n")); err != nil {
		t.Errorf("dns-updown disable rejected: %v", err)
	}
	for _, d := range []string{"dns-updown force", "dns-updown /Users/x/evil.sh", "--dns-updown /bin/sh", "dns-updown"} {
		if err := ValidateOVPN([]byte(base + d + "\n")); err == nil {
			t.Errorf("%q accepted, want rejection", d)
		}
	}
}

func TestLegacyDataCiphers(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cipher AES-256-CBC\n", defaultDataCiphers + ":AES-256-CBC"},
		{"cipher AES-256-CBC\ndata-ciphers AES-256-GCM\n", ""},
		{"cipher AES-256-GCM\n", ""},
		{"cipher BF-CBC\n", ""},
		{"cipher none\n", ""},
		{"", ""},
		{"cipher AES;rm\n", ""},
		{"<key>\ncipher AES-128-CBC\n</key>\n", ""},
		{"--cipher AES-128-CBC\n", defaultDataCiphers + ":AES-128-CBC"},
	}
	for _, c := range cases {
		p, err := inspectProfile([]byte(vbase + c.in))
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if p.legacyCiphers != c.want {
			t.Errorf("legacyCiphers(%q) = %q, want %q", c.in, p.legacyCiphers, c.want)
		}
	}
}

func TestRuntimeVerb(t *testing.T) {
	for body, want := range map[string]string{"": "3", "verb 1\n": "3", "verb 3\n": "3", "verb 4\n": "4", "verb 9\n": "4", "setenv opt verb 11\n": "4"} {
		p, err := inspectProfile([]byte(vbase + body))
		if err != nil {
			t.Fatal(err)
		}
		if got := p.runtimeVerb(); got != want {
			t.Errorf("%q: verb %s, want %s", body, got, want)
		}
	}
}

func TestRuntimeConfigStripsUserGroup(t *testing.T) {
	in := vbase + "user nobody\r\n\"group\" nogroup\nverb 3\n<ca>\nuser x\n</ca>\n"
	p, err := inspectProfile([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out := string(p.runtimeConfig([]byte(in)))
	want := vbase + "\n\nverb 3\n<ca>\nuser x\n</ca>\n"
	if out != want {
		t.Errorf("runtimeConfig = %q, want %q", out, want)
	}
	if err := ValidateOVPN([]byte(out)); err != nil {
		t.Errorf("stripped config invalid: %v", err)
	}
	ds, _ := parseConfig([]byte(out))
	walkDirectives(ds, func(d *directive) bool {
		if !d.Inline && stripOnly[d.Name] {
			t.Errorf("%s survived", d.Name)
		}
		return true
	})
}

func TestArgs(t *testing.T) {
	p, err := inspectProfile([]byte(vbase + "cipher AES-256-CBC\nverb 7\n"))
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join((&Manager{}).args("/r/x.ovpn", "/r/x.sock", p), " ")
	for _, want := range []string{"--config /r/x.ovpn ", "--verb 4", "--ping 10 --ping-restart 60", "--mssfix 1300", "--data-ciphers " + defaultDataCiphers + ":AES-256-CBC", "--auth-retry interact"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
	if strings.Contains(args, "IV_SSO") {
		t.Error("IV_SSO must not be advertised")
	}
	if !strings.HasPrefix(args, "--config ") {
		t.Error("--config must come first so later flags override the profile")
	}
}

// TestArgsAcceptedByOpenVPN parses our argv (plus a stripped user/group
// profile) with the bundled binary; "--version" exits after option parsing.
func TestArgsAcceptedByOpenVPN(t *testing.T) {
	bin, _ := filepath.Abs("../../build/openvpn/bin/openvpn")
	if _, err := os.Stat(bin); err != nil || testing.Short() {
		t.Skip("bundled openvpn binary not available")
	}
	in := []byte(vbase + "user nobody\ngroup nobody\nproviders legacy default\ncipher AES-256-CBC\n")
	p, err := inspectProfile(in)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "x.ovpn")
	if err := os.WriteFile(cfg, p.runtimeConfig(in), 0600); err != nil {
		t.Fatal(err)
	}
	args := append((&Manager{}).args(cfg, filepath.Join(dir, "x.sock"), p), "--version")
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "OpenVPN 2.") {
		t.Fatalf("openvpn rejected argv: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "Options error") {
		t.Errorf("options error:\n%s", out)
	}
}
