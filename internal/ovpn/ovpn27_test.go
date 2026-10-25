package ovpn

import (
	"reflect"
	"testing"
)

func TestExtractPushedDNS(t *testing.T) {
	cases := []struct {
		name, line string
		want       []string
	}{
		{
			"dhcp-option",
			"PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 192.168.1.11,dhcp-option DOMAIN corp.local,ifconfig 10.8.0.2 255.255.255.0'",
			[]string{"192.168.1.11", "corp.local"},
		},
		{
			"dhcp-option DNS6 and DOMAIN-SEARCH, last option",
			"PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS6 fd00::1,dhcp-option DOMAIN-SEARCH a.example'",
			[]string{"fd00::1", "a.example"},
		},
		{
			"dns server wins over dhcp-option",
			"PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 1.1.1.1,dns server 0 address 10.8.0.1 10.8.0.2:5353 [fd00::1]:53 fd00::2,dns search-domains corp.example b.example,route-gateway 10.8.0.1'",
			[]string{"10.8.0.1", "10.8.0.2", "fd00::1", "fd00::2", "corp.example", "b.example"},
		},
		{
			"push update",
			"PUSH: Received control message: 'PUSH_UPDATE,-dns,dns server 1 address 10.9.0.1'",
			[]string{"10.9.0.1"},
		},
		{
			"no dns",
			"PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,dns server 0 resolve-domains x.example'",
			nil,
		},
	}
	for _, c := range cases {
		if got := extractPushedDNS(c.line); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
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
		{"client\ncipher AES-256-CBC\n", defaultDataCiphers + ":AES-256-CBC"},
		{"cipher AES-256-CBC\ndata-ciphers AES-256-GCM\n", ""},
		{"cipher AES-256-GCM\n", ""},
		{"cipher BF-CBC\n", ""},
		{"cipher none\n", ""},
		{"client\n", ""},
		{"cipher AES;rm\n", ""},
		{"<key>\ncipher AES-128-CBC\n</key>\n", ""},
		{"--cipher AES-128-CBC\n", defaultDataCiphers + ":AES-128-CBC"},
	}
	for _, c := range cases {
		if got := LegacyDataCiphers([]byte(c.in)); got != c.want {
			t.Errorf("LegacyDataCiphers(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
