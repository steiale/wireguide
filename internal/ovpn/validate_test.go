package ovpn

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const vbase = "client\nremote vpn.example.com 1194\n"

// Every bypass from the security review, plus the file-touching and
// exec directives the allowlist must refuse.
func TestValidateOVPNRejects(t *testing.T) {
	long := strings.Repeat("A", 255)
	cases := map[string]string{
		// Finding 1: file-writing / file-reading / process-state directives.
		"log":                  "log /Library/x\n",
		"log-append":           "log-append /Library/x\n",
		"status":               "status /Library/x 1\n",
		"status-version":       "status-version 2\n",
		"writepid":             "writepid /Library/x\n",
		"tls-export-cert":      "tls-export-cert /Library/x\n",
		"genkey":               "genkey secret /Library/x\n",
		"config":               "config /Library/x.ovpn\n",
		"cd":                   "cd /\n",
		"chroot":               "chroot /var/empty\n",
		"tmp-dir":              "tmp-dir /Library\n",
		"setenv opt user":      "setenv opt user nobody\n",
		"user in connection":   "<connection>\nremote h 1\ngroup nobody\n</connection>\n",
		"lport privileged":     "lport 53\n",
		"lport service":        "lport domain\n",
		"local privileged":     "local 0.0.0.0 80\n",
		"setenv opt lport":     "setenv opt lport 22\n",
		"port with bind":       "port 53\nbind\n",
		"port with local":      "port 53\nlocal 10.0.0.1\n",
		"daemon":               "daemon\n",
		"inetd":                "inetd\n",
		"management":           "management 127.0.0.1 7505\n",
		"management-hold":      "management-hold\n",
		"management-client":    "management-client\n",
		"auth-user-pass file":  "auth-user-pass /etc/master.passwd\n",
		"auth-user-pass uonly": "auth-user-pass username-only\n",
		"askpass":              "askpass /etc/x\n",
		"ca path":              "ca /etc/x\n",
		"cert path":            "cert /etc/x\n",
		"key path":             "key /etc/x\n",
		"pkcs12 path":          "pkcs12 /etc/x\n",
		"tls-auth path":        "tls-auth /etc/x 1\n",
		"tls-crypt path":       "tls-crypt /etc/x\n",
		"tls-crypt-v2 path":    "tls-crypt-v2 /etc/x\n",
		"crl-verify path":      "crl-verify /etc/x\n",
		"crl-verify dir":       "crl-verify /etc dir\n",
		"dh path":              "dh /etc/x\n",
		"extra-certs path":     "extra-certs /etc/x\n",
		"secret path":          "secret /etc/x\n",
		"secret inline":        "<secret>\nx\n</secret>\n",
		"proxy-user-pass path": "http-proxy-user-pass /etc/x\n",
		"http-proxy authfile":  "http-proxy p.example 8080 /etc/x basic\n",
		"socks-proxy authfile": "socks-proxy p.example 1080 /etc/x\n",
		// Exec / library loading.
		"up":               "up /x\n",
		"down":             "down /x\n",
		"route-up":         "route-up /x\n",
		"route-pre-down":   "route-pre-down /x\n",
		"tls-verify":       "tls-verify /x\n",
		"ipchange":         "ipchange /x\n",
		"plugin":           "plugin /x.so\n",
		"iproute":          "iproute /x\n",
		"engine":           "engine dynamic\n",
		"providers module": "providers /x.so\n",
		"providers fips":   "providers legacy fips\n",
		"pkcs11-providers": "pkcs11-providers /x.so\n",
		"dns-updown force": "dns-updown force\n",
		"dns-updown path":  "dns-updown /x\n",
		"dev tap":          "dev tap\n",
		"dev path":         "dev ../../x\n",
		"dev-type tap":     "dev-type tap\n",
		"dev-node":         "dev-node /dev/x\n",
		"inline up":        "<up>\n/x\n</up>\n",
		"inline log":       "<log>\nx\n</log>\n",
		"inline config":    "<config>\nx\n</config>\n",
		"unknown":          "foo-bar 1\n",
		"case variant":     "UP /x\n",
		// setenv: env is exported to route/ifconfig run as root, and
		// "setenv opt X" is the directive X.
		"setenv PATH":         "setenv PATH /x\n",
		"setenv DYLD":         "setenv DYLD_INSERT_LIBRARIES /x.dylib\n",
		"setenv GENERIC":      "setenv GENERIC_CONFIG 1\n",
		"setenv opt up":       "setenv opt up /x\n",
		"setenv opt log":      "setenv opt log /x\n",
		"setenv opt quoted":   "setenv opt \"up\" /x\n",
		"setenv opt nested":   "setenv opt setenv opt up /x\n",
		"setenv opt empty":    "setenv opt\n",
		"setenv opt --up":     "setenv opt --up /x\n",
		"setenv opt ca path":  "setenv opt ca /etc/x\n",
		"setenv-safe badname": "setenv-safe A=B x\n",
		// Finding 2: tokenizer mismatch.
		"double quoted":   "\"up\" /x\n",
		"single quoted":   "'up' /x\n",
		"escaped space":   "\\ up /x\n",
		"leading dashes":  "--up /x\n",
		"quoted dashes":   "\"--up\" /x\n",
		"dashes log":      "--log /x\n",
		"bad backslash":   "\\up /x\n",
		"tab separated":   "up\t/x\n",
		"vtab prefix":     "\vup /x\n",
		"crlf":            "up /x\r\n",
		"bom":             "\xEF\xBB\xBFup /x\n",
		"unclosed quote":  "remote \"x\n",
		"unclosed squote": "remote 'x\n",
		"NUL byte":        "verb 3\x00\nup /x\n",
		"line too long":   "# " + strings.Repeat("x", 300) + "\n",
		"param too long":  "remote " + strings.Repeat("x", 240) + "\"" + strings.Repeat("y", 20) + "\"\n",
		// Finding 3: inline close tag is a prefix match in openvpn.
		"close tag suffix":     "<ca>\nx\n</ca>junk\nup /x\n",
		"close tag space":      "<ca>\nx\n</ca> trailing\nlog /x\n",
		"close tag indented":   "<ca>\nx\n   </ca>\nstatus /x\n",
		"close tag chunked":    "<ca>\n" + long + "</ca>\nup /x\n",
		"chunk remainder line": "<ca>\n" + long + "</ca>" + strings.Repeat("B", 250) + "up /x\n",
		"opener with comment":  "<ca> # x\nx\n</ca>\nup /x\n",
		"quoted opener":        "\"<ca>\"\nx\n</ca>\nup /x\n",
		"dashed opener":        "--<ca>\nx\n</ca>\nup /x\n",
		"missing end tag":      "<ca>\nx\n",
		"inline in conn hide":  "<connection>\nremote h 1\n<tls-auth>\nx\n</tls-auth>junk\nup /x\n</connection>\n",
		// <connection> blocks hold real directives.
		"conn up":           "<connection>\nremote h 1194\nup /x\n</connection>\n",
		"conn close suffix": "<connection>\nremote h 1194\n</connection>x\nup /x\n",
		"conn nested":       "<connection>\nremote h 1\n<connection>\nremote h 2\n</connection>\n</connection>\n",
		"conn ca path":      "<connection>\nremote h 1\nca /etc/x\n</connection>\n",
		"conn long line":    "<connection>\nremote h 1\n# " + strings.Repeat("x", 300) + "\n</connection>\n",
	}
	for name, body := range cases {
		if err := ValidateOVPN([]byte(vbase + body)); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}
	// Server configs / missing remote still rejected.
	for _, s := range []string{"remote h 1\n", "client\n", "server 10.8.0.0 255.255.255.0\nclient\nremote h 1\n"} {
		if ValidateOVPN([]byte(s)) == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestValidateOVPNErrorNamesDirectiveAndLine(t *testing.T) {
	err := ValidateOVPN([]byte(vbase + "verb 3\n\"log\" /secret/path\n"))
	if err == nil {
		t.Fatal("accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"log"`) || !strings.Contains(msg, "line 4") {
		t.Errorf("error %q should name directive and line", msg)
	}
	if strings.Contains(msg, "/secret/path") {
		t.Errorf("error %q leaks the argument", msg)
	}
}

// Typical real-world client profiles must keep working.
func TestValidateOVPNAccepts(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	cases := map[string]string{
		"minimal": vbase,
		"provider": `client
dev tun
proto udp
remote vpn.example.com 1194
remote vpn2.example.com 443 tcp
remote-random
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server.example.com name
auth SHA512
cipher AES-256-CBC
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
key-direction 1
comp-lzo no
allow-compression no
verb 3
mute 20
mute-replay-warnings
auth-user-pass
auth-nocache
auth-retry nointeract
static-challenge "Enter OTP" 1
push-peer-info
pull-filter ignore "route-ipv6"
route 10.0.0.0 255.0.0.0 vpn_gateway
route-ipv6 fd00::/8
redirect-gateway def1 bypass-dhcp
block-ipv6
dhcp-option DNS 10.8.0.1
dns server 0 address 10.8.0.1
dns-updown disable
tun-mtu 1500
mssfix 1450
keepalive 10 60
ping-timer-rem
connect-retry 2 30
connect-retry-max 5
connect-timeout 10
server-poll-timeout 4
hand-window 60
reneg-sec 0
float
explicit-exit-notify 2
sndbuf 393216
rcvbuf 393216
http-proxy proxy.example 8080 auto
socks-proxy 127.0.0.1 1080
script-security 2
setenv opt block-outside-dns
ignore-unknown-option block-outside-dns
setenv FORWARD_COMPATIBLE 1
setenv UV_ID abc
setenv-safe FOO bar
# comment
; comment
<ca>
` + pem + `</ca>
<cert>
` + pem + `</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIB
-----END PRIVATE KEY-----
</key>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
abcd
-----END OpenVPN Static key V1-----
</tls-auth>
`,
		"connection blocks + inline creds": `client
dev tun
<connection>
remote a.example 1194 udp
connect-timeout 5
</connection>
<connection>
remote b.example 443
proto tcp-client
http-proxy p.example 3128
</connection>
<auth-user-pass>
user
pass
</auth-user-pass>
<tls-crypt>
x
</tls-crypt>
<http-proxy-user-pass>
u
p
</http-proxy-user-pass>
peer-fingerprint AB:CD
`,
		"double dash + quotes + crlf": "--client\r\n\"remote\" 'vpn.example.com' 1194\r\ndev utun\r\n",
		"bom":                         "\xEF\xBB\xBF" + vbase,
		"long inline line":            vbase + "<ca>\n" + strings.Repeat("A", 600) + "\n</ca>\n",
		"dev-type tun":                vbase + "dev tun0\ndev-type tun\n",
		"linux user/group":            vbase + "user nobody\ngroup nogroup\n",
		"providers":                   vbase + "providers legacy default\n",
		"remote port below 1024":      vbase + "port 443\n",
		"unprivileged local ports":    vbase + "lport 0\nlport 50000\nlocal 10.0.0.1 50000\nbind\nport 1194\n",
	}
	for name, body := range cases {
		if err := ValidateOVPN([]byte(body)); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
}

func TestParseLine(t *testing.T) {
	cases := []struct {
		in   string
		want []string
		err  bool
	}{
		{"remote a 1\n", []string{"remote", "a", "1"}, false},
		{"  \"up\" /x\n", []string{"up", "/x"}, false},
		{"'a b' c\n", []string{"a b", "c"}, false},
		{"'a\\b'\n", []string{"a\\b"}, false},
		{"\"a\\\"b\"\n", []string{"a\"b"}, false},
		{"a\\ b\n", []string{"a b"}, false},
		{"\\ up\n", []string{"up"}, false},
		{"\\up\n", nil, true},
		{"# x\n", nil, false},
		{"; x\n", nil, false},
		{"\\# x\n", nil, false},
		{"a #b\n", []string{"a"}, false},
		{"a#b\n", []string{"a#b"}, false},
		{"\"a\"b\n", []string{"a", "b"}, false},
		{"\"\"\n", []string{""}, false},
		{"\"abc\n", nil, true},
		{"'abc\n", nil, true},
		{strings.Repeat("a ", 20), strings.Split(strings.Repeat("a ", 16), " ")[:16], false},
	}
	for _, c := range cases {
		got, err := parseLine(c.in)
		if (err != nil) != c.err || (!c.err && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("parseLine(%q) = %q, %v; want %q, err=%v", c.in, got, err, c.want, c.err)
		}
	}
}

func TestHelpersUseSameTokenizer(t *testing.T) {
	// A keepalive hidden from the old scanner by a prefix close tag.
	inspect := func(body string) *profile {
		t.Helper()
		p, err := inspectProfile([]byte(vbase + body))
		if err != nil {
			t.Fatalf("inspectProfile(%q): %v", body, err)
		}
		return p
	}
	if !inspect("<ca>\nx\n</ca>junk\nkeepalive 10 60\n").hasKeepalive {
		t.Error("missed keepalive after prefix close tag")
	}
	if !inspect("\"mssfix\" 1400\n").hasMTU {
		t.Error("missed quoted mssfix")
	}
	if inspect("<ca>\nmssfix 1400\n</ca>\n").hasMTU {
		t.Error("looked inside inline block")
	}
	if !inspect("setenv opt keepalive 10 60\n").hasKeepalive {
		t.Error("missed keepalive behind setenv opt")
	}
	cfg, err := ParseOVPN([]byte("<connection>\n'remote' h.example 443\n</connection>\nauth-user-pass\n"))
	if err != nil || cfg.Remote != "h.example:443" || !cfg.AuthUserPass {
		t.Errorf("ParseOVPN = %+v, %v", cfg, err)
	}
	cfg, _ = ParseOVPN([]byte("<auth-user-pass>\nu\np\n</auth-user-pass>\n"))
	if cfg.AuthUserPass {
		t.Error("inline credentials should not require a prompt")
	}
}

// TestDifferentialAgainstOpenVPN runs the bundled openvpn on crafted files
// and checks that its view of which directives exist matches ours. A probe
// directive "lockplus-probe" (unknown to openvpn) is placed where the old
// validator could not see it; openvpn reports "Unrecognized option ...
// lockplus-probe" iff it parsed it as a directive. "--version" after
// --config makes openvpn exit right after parsing, without connecting.
func TestDifferentialAgainstOpenVPN(t *testing.T) {
	bin, _ := filepath.Abs("../../build/openvpn/bin/openvpn")
	if _, err := os.Stat(bin); err != nil || testing.Short() {
		t.Skip("bundled openvpn binary not available")
	}
	long := strings.Repeat("A", 255)
	const probe = "lockplus-probe"
	cases := map[string]string{
		"plain":                 probe + " x\n",
		"double quoted":         "\"" + probe + "\" x\n",
		"single quoted":         "'" + probe + "'\n",
		"escaped space":         "\\ " + probe + "\n",
		"double dash":           "--" + probe + "\n",
		"crlf":                  probe + "\r\n",
		"vtab":                  "\v" + probe + "\n",
		"bom first line":        "\xEF\xBB\xBF" + probe + "\n" + vbase,
		"comment hash":          "# " + probe + "\n",
		"comment semicolon":     "; " + probe + "\n",
		"escaped hash":          "\\# " + probe + "\n",
		"bad backslash":         "\\" + probe + "\n",
		"unclosed quote":        "\"" + probe + "\n",
		"close tag suffix":      "<ca>\nx\n</ca>junk\n" + probe + "\n",
		"close tag indented":    "<ca>\nx\n \t</ca>\n" + probe + "\n",
		"inside inline":         "<ca>\n" + probe + "\n</ca>\n",
		"opener with comment":   "<ca> # c\n" + probe + "\n</ca>\n",
		"quoted opener":         "\"<ca>\"\n" + probe + "\n</ca>\n",
		"dashed opener":         "--<ca>\n" + probe + "\n</ca>\n",
		"close tag chunked":     "<ca>\n" + long + "</ca>\n" + probe + "\n",
		"chunk remainder":       "<ca>\n" + long + "</ca>" + strings.Repeat("B", 250) + probe + "\n",
		"long inline no close":  "<ca>\n" + strings.Repeat("A", 600) + "\n</ca>\n" + probe + "\n",
		"setenv opt":            "setenv opt " + probe + "\n",
		"conn inside":           "<connection>\nremote 127.0.0.1 1\n" + probe + "\n</connection>\n",
		"conn close suffix":     "<connection>\nremote 127.0.0.1 1\n</connection>x\n" + probe + "\n",
		"conn inline prefix":    "<connection>\nremote 127.0.0.1 1\n<tls-auth>\nx\n</tls-auth>junk\n" + probe + "\n</connection>\n",
		"conn inline hides":     "<connection>\nremote 127.0.0.1 1\n<tls-auth>\n" + probe + "\n</tls-auth>\n</connection>\n",
		"conn closes in inline": "<connection>\nremote 127.0.0.1 1\n<tls-auth>\n</connection>\n" + probe + "\n</tls-auth>\n</connection>\n",
		"too long top line":     "# " + strings.Repeat("x", 300) + probe + "\n",
		"none":                  "verb 3\n",
	}
	dir := t.TempDir()
	for name, body := range cases {
		content := vbase + body
		if strings.HasPrefix(body, "\xEF\xBB\xBF") {
			content = body
		}
		f := filepath.Join(dir, "case.ovpn")
		if err := os.WriteFile(f, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, _ := exec.CommandContext(ctx, bin, "--config", f, "--version").CombinedOutput()
		cancel()
		ovSees := strings.Contains(string(out), "Unrecognized option") && strings.Contains(string(out), probe)
		ovOK := ovSees || strings.Contains(string(out), "OpenVPN 2.7")

		ds, perr := parseConfig([]byte(content))
		weSee := false
		walkDirectives(ds, func(d *directive) bool {
			if d.Name == probe || (d.Name == "setenv" && len(d.Args) > 1 && d.Args[0] == "opt" && d.Args[1] == probe) {
				weSee = true
			}
			return true
		})
		t.Logf("%-22s openvpn: parsed=%v sees=%v | ours: err=%v sees=%v", name, ovOK, ovSees, perr != nil, weSee)
		switch {
		case ovSees && perr == nil && !weSee:
			t.Errorf("%s: BYPASS: openvpn parses the probe directive, our parser does not", name)
		case perr == nil && weSee != ovSees:
			t.Errorf("%s: mismatch: openvpn sees probe=%v, we see=%v\n%s", name, ovSees, weSee, out)
		case perr != nil && ovOK && !ovSees:
			// We are stricter than openvpn here; acceptable but log it.
			t.Logf("%s: we reject (%v), openvpn parses it", name, perr)
		case perr == nil && !ovOK:
			t.Errorf("%s: openvpn fails to parse but we accept\n%s", name, out)
		}
	}
}
