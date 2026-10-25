// Package ovpn implements OpenVPN support: .ovpn validation and analysis,
// Keychain credentials, and supervising the bundled openvpn binary over its
// management interface.
package ovpn

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// OVPNConfig is the subset of an .ovpn file LockPlus needs for display and
// the kill switch. The file itself is passed to openvpn (minus user/group).
type OVPNConfig struct {
	Remote       string // first "remote <host> [port]", IPv6 hosts bracketed when a port follows
	Proto        string // "udp" | "tcp" | "tcp-client" etc., empty if unspecified
	AuthUserPass bool   // bare auth-user-pass present (credentials prompted)

	// Remotes is every remote openvpn may try (top level and <connection>
	// blocks, in file order), so the kill switch can pass all of them while
	// a multi-remote or remote-random profile reconnects.
	Remotes []RemoteSpec
}

// RemoteSpec is one "remote host [port [proto]]" with the profile's
// defaults (port/rport, proto, also per <connection> block) filled in.
type RemoteSpec struct {
	Host  string // hostname or IP literal, unbracketed
	Port  string
	Proto string // "udp" or "tcp"
}

// transportProto folds openvpn's proto variants (tcp-client, tcp4, udp6...)
// into "udp" or "tcp".
func transportProto(p string) string {
	if strings.HasPrefix(strings.ToLower(p), "tcp") {
		return "tcp"
	}
	return "udp"
}

// profile is everything Connect needs from a validated .ovpn, gathered in
// one pass.
type profile struct {
	cfg           OVPNConfig
	hasKeepalive  bool   // ping/ping-restart/keepalive set
	hasMTU        bool   // mssfix/fragment/tun-mtu/link-mtu set
	legacyCiphers string // --data-ciphers shim, "" if not needed
	verb          int    // -1 if absent
	dns           dnsConfig
	pullFilters   []pullFilter
	stripLines    []int // 1-based lines of top-level user/group directives
}

// defaultDataCiphers is OpenVPN 2.7's built-in --data-ciphers default.
const defaultDataCiphers = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

// maxOVPNSize bounds an imported profile.
const maxOVPNSize = 1 << 20

// stripOnly directives are accepted at top level but removed from the
// runtime config: user/group would make root openvpn drop privileges and
// then fail route teardown. Common in Linux-oriented exports.
var stripOnly = map[string]bool{"user": true, "group": true}

// ValidateOVPN decides whether an untrusted .ovpn may be handed to the
// root-run openvpn binary: it must parse exactly as openvpn parses it
// (parse.go), every directive (including <connection> children and
// "setenv opt" payloads) must be on the allowlist (allowlist.go), and it must
// be a client config with a remote.
func ValidateOVPN(data []byte) error {
	_, err := inspectProfile(data)
	return err
}

// inspectProfile validates data and extracts what Connect needs.
func inspectProfile(data []byte) (*profile, error) {
	if len(data) > maxOVPNSize {
		return nil, fmt.Errorf("invalid .ovpn: file is larger than %d bytes", maxOVPNSize)
	}
	ds, err := parseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("invalid .ovpn: %w", err)
	}
	p := &profile{verb: -1}
	var (
		hasRemote, hasClient, pull, bind bool
		lowPort                          []int // lines of "port N" with N < 1024
		cipher                           string
		explicitCiphers                  bool
	)
	visit := func(d *directive, topLevel bool) error {
		if err := checkDirective(d); err != nil {
			return err
		}
		if stripOnly[d.Name] {
			if !topLevel {
				return fmt.Errorf("directive %q is not allowed inside <connection>", d.Name)
			}
			p.stripLines = append(p.stripLines, d.Line)
			return nil
		}
		if d.Inline {
			return nil
		}
		name, args := effective(d)
		switch name {
		case "remote":
			hasRemote = true
		case "client":
			hasClient, pull = true, true
		case "tls-client":
			hasClient = true
		case "pull":
			pull = true
		case "bind":
			bind = true
		case "local":
			if len(args) < 2 {
				bind = true // binds to the "port"/default local port
			}
		case "port":
			if len(args) == 1 && !unprivilegedPort(args[0]) {
				lowPort = append(lowPort, d.Line)
			}
		case "ping", "ping-restart", "keepalive":
			p.hasKeepalive = true
		case "mssfix", "fragment", "tun-mtu", "link-mtu":
			p.hasMTU = true
		case "data-ciphers", "ncp-ciphers":
			explicitCiphers = true
		case "cipher":
			if len(args) > 0 {
				cipher = args[0]
			}
		case "verb":
			if len(args) == 1 {
				if v, err := strconv.Atoi(args[0]); err == nil {
					p.verb = v
				}
			}
		case "dns", "dhcp-option":
			p.dns.add(name, args)
		case "pull-filter":
			if len(args) == 2 {
				p.pullFilters = append(p.pullFilters, pullFilter{action: args[0], prefix: args[1]})
			}
		}
		return nil
	}
	for i := range ds {
		if err := visit(&ds[i], true); err != nil {
			return nil, fmt.Errorf("invalid .ovpn: line %d: %w", ds[i].Line, err)
		}
		for j := range ds[i].Children {
			c := &ds[i].Children[j]
			if err := visit(c, false); err != nil {
				return nil, fmt.Errorf("invalid .ovpn: line %d: %w", c.Line, err)
			}
		}
	}
	if !hasRemote {
		return nil, fmt.Errorf("invalid .ovpn: no 'remote' directive found")
	}
	if !hasClient {
		return nil, fmt.Errorf("invalid .ovpn: missing 'client' or 'tls-client' directive (is this a server config?)")
	}
	// "port" sets the local port too; it is only bound when something forces
	// a local bind (or without pull). See options.c need_bind.
	if len(lowPort) > 0 && (bind || !pull) {
		return nil, fmt.Errorf("invalid .ovpn: line %d: directive \"port\": binding a local port below 1024 is not allowed; use 'rport' for the server port", lowPort[0])
	}
	p.cfg = summarize(ds)
	if !explicitCiphers {
		p.legacyCiphers = legacyDataCiphers(cipher)
	}
	return p, nil
}

// effective resolves "setenv opt X args" to the directive openvpn applies.
func effective(d *directive) (string, []string) {
	if d.Name == "setenv" && len(d.Args) >= 2 && d.Args[0] == "opt" {
		return d.Args[1], d.Args[2:]
	}
	return d.Name, d.Args
}

// legacyDataCiphers restores 2.6's implicit behaviour for profiles that set
// `cipher X` without `data-ciphers`: 2.6 appended X to the negotiable list,
// 2.7 ignores it, so a CBC-only server stops connecting. BF-CBC is skipped
// (2.7 still translates it itself); `none` is never re-enabled.
func legacyDataCiphers(cipher string) string {
	if cipher == "" || !isCipherName(cipher) {
		return ""
	}
	upper := strings.ToUpper(cipher)
	if upper == "NONE" || upper == "BF-CBC" {
		return ""
	}
	for _, c := range strings.Split(defaultDataCiphers, ":") {
		if upper == c {
			return ""
		}
	}
	return defaultDataCiphers + ":" + cipher
}

func isCipherName(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

// runtimeVerb picks the --verb passed after --config: at least 3, because
// pushed DNS and the cipher are scraped from D_PUSH (3) log lines, and at
// most 4, because 7+ logs data-channel keys and 9 plaintext packets.
func (p *profile) runtimeVerb() string {
	v := p.verb
	if v < 3 {
		v = 3
	}
	if v > 4 {
		v = 4
	}
	return strconv.Itoa(v)
}

// runtimeConfig returns data with the strip-only directives blanked out
// (lines kept so openvpn's error line numbers still match the profile).
func (p *profile) runtimeConfig(data []byte) []byte {
	if len(p.stripLines) == 0 {
		return data
	}
	drop := make(map[int]bool, len(p.stripLines))
	for _, l := range p.stripLines {
		drop[l] = true
	}
	lines := strings.SplitAfter(string(data), "\n")
	var b strings.Builder
	for i, l := range lines {
		if drop[i+1] {
			if strings.HasSuffix(l, "\n") {
				b.WriteByte('\n')
			}
			continue
		}
		b.WriteString(l)
	}
	return []byte(b.String())
}

// ParseOVPN extracts display/kill-switch fields. It does not enforce the
// allowlist but uses the same tokenizer as openvpn.
func ParseOVPN(data []byte) (*OVPNConfig, error) {
	ds, err := parseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("reading ovpn config: %w", err)
	}
	cfg := summarize(ds)
	return &cfg, nil
}

// remoteDefaults are the proto and port a "remote" without them inherits.
type remoteDefaults struct{ proto, port string }

// apply updates defaults from a proto/port/rport directive.
func (rd *remoteDefaults) apply(d *directive) {
	if d.Inline || len(d.Args) < 1 {
		return
	}
	switch d.Name {
	case "proto":
		rd.proto = d.Args[0]
	case "port", "rport":
		rd.port = d.Args[0]
	}
}

// collectRemotes lists every remote in file order. A <connection> block
// inherits the top-level proto/port and may override them.
func collectRemotes(ds []directive) []RemoteSpec {
	global := remoteDefaults{proto: "udp", port: "1194"}
	for i := range ds {
		global.apply(&ds[i])
	}
	var out []RemoteSpec
	add := func(d *directive, def remoteDefaults) {
		if d.Inline || len(d.Args) < 1 || d.Args[0] == "" {
			return
		}
		r := RemoteSpec{Host: strings.Trim(d.Args[0], "[]"), Port: def.port, Proto: transportProto(def.proto)}
		if len(d.Args) >= 2 && d.Args[1] != "" {
			r.Port = d.Args[1]
		}
		if len(d.Args) >= 3 && d.Args[2] != "" {
			r.Proto = transportProto(d.Args[2])
		}
		out = append(out, r)
	}
	for i := range ds {
		d := &ds[i]
		if d.Name == "remote" {
			add(d, global)
		}
		if len(d.Children) == 0 {
			continue
		}
		local := global
		for j := range d.Children {
			local.apply(&d.Children[j])
		}
		for j := range d.Children {
			if d.Children[j].Name == "remote" {
				add(&d.Children[j], local)
			}
		}
	}
	return out
}

func summarize(ds []directive) OVPNConfig {
	var cfg OVPNConfig
	cfg.Remotes = collectRemotes(ds)
	walkDirectives(ds, func(d *directive) bool {
		switch d.Name {
		case "remote":
			if cfg.Remote == "" && len(d.Args) >= 1 {
				host := d.Args[0]
				if len(d.Args) >= 2 {
					// Bracket IPv6 so host:port stays unambiguous for
					// net.SplitHostPort.
					if strings.Contains(host, ":") {
						host = "[" + host + "]"
					}
					host += ":" + d.Args[1]
				}
				cfg.Remote = host
			}
		case "proto":
			if len(d.Args) >= 1 {
				cfg.Proto = strings.ToLower(d.Args[0])
			}
		case "auth-user-pass":
			// Inline credentials are used directly; only the bare form prompts.
			if !d.Inline {
				cfg.AuthUserPass = true
			}
		}
		return true
	})
	return cfg
}

// pullFilter is a profile "pull-filter accept|ignore|reject <prefix>".
type pullFilter struct {
	action, prefix string
}

// filterPushed mirrors apply_pull_filter: the first filter whose prefix
// matches wins. keep is false for ignore; ok is false for reject (openvpn
// then fails the whole push).
func filterPushed(filters []pullFilter, opt string) (keep, ok bool) {
	for _, f := range filters {
		if strings.HasPrefix(opt, f.prefix) {
			switch f.action {
			case "accept":
				return true, true
			case "ignore":
				return false, true
			case "reject":
				return false, false
			}
		}
	}
	return true, true
}

// dnsConfig collects DNS options the way openvpn 2.7 does: `dns server N`
// entries keyed by priority (a pushed priority replaces the profile's), and
// dhcp-option DNS/DOMAIN, which openvpn ignores once any `dns server` exists.
type dnsConfig struct {
	servers     map[int][]string
	search      []string
	dhcpServers []string
	dhcpDomains []string
	touched     bool // any DNS option seen (including ones carrying no address)
}

// add records one "dns ..." or "dhcp-option ..." directive.
func (c *dnsConfig) add(name string, args []string) {
	c.touched = true
	switch name {
	case "dhcp-option":
		if len(args) < 2 {
			return
		}
		switch args[0] {
		case "DNS", "DNS6":
			c.dhcpServers = append(c.dhcpServers, args[1])
		case "DOMAIN", "DOMAIN-SEARCH":
			c.dhcpDomains = append(c.dhcpDomains, args[1])
		}
	case "dns":
		switch {
		case len(args) >= 4 && args[0] == "server" && args[2] == "address":
			prio, err := strconv.Atoi(args[1])
			if err != nil {
				return
			}
			if c.servers == nil {
				c.servers = map[int][]string{}
			}
			for _, a := range args[3:] {
				if ip := stripDNSPort(a); ip != "" {
					c.servers[prio] = append(c.servers[prio], ip)
				}
			}
		case len(args) >= 2 && args[0] == "search-domains":
			c.search = append(c.search, args[1:]...)
		}
	}
}

// merge returns the profile config c overlaid with pushed config.
func (c dnsConfig) merge(pushed dnsConfig) dnsConfig {
	out := dnsConfig{
		servers:     map[int][]string{},
		search:      append(append([]string{}, c.search...), pushed.search...),
		dhcpServers: append(append([]string{}, c.dhcpServers...), pushed.dhcpServers...),
		dhcpDomains: append(append([]string{}, c.dhcpDomains...), pushed.dhcpDomains...),
	}
	for k, v := range c.servers {
		out.servers[k] = v
	}
	for k, v := range pushed.servers {
		out.servers[k] = v
	}
	return out
}

// entries returns server IPs followed by search domains, deduplicated, in
// the mixed form network.SetDNS takes.
func (c dnsConfig) entries() []string {
	var out []string
	seen := map[string]bool{}
	add := func(vs ...string) {
		for _, v := range vs {
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	if len(c.servers) > 0 {
		prios := make([]int, 0, len(c.servers))
		for k := range c.servers {
			prios = append(prios, k)
		}
		sort.Ints(prios)
		for _, k := range prios {
			add(c.servers[k]...)
		}
		add(c.search...)
		return out
	}
	add(c.dhcpServers...)
	add(c.dhcpDomains...)
	return out
}

// stripDNSPort turns "1.2.3.4", "1.2.3.4:53", "fd00::1" or "[fd00::1]:53"
// into a bare IP; "" for anything else.
func stripDNSPort(s string) string {
	if net.ParseIP(s) != nil {
		return s
	}
	if host, _, err := net.SplitHostPort(s); err == nil && net.ParseIP(host) != nil {
		return host
	}
	return ""
}

// pushMessage is one logged PUSH_REPLY/PUSH_UPDATE after pull-filter.
type pushMessage struct {
	update   bool
	more     bool // push-continuation 2: another message follows
	dns      dnsConfig
	rejected bool // a reject filter matched; openvpn discards the push
}

// parsePushLine decodes openvpn's
// "PUSH: Received control message: 'PUSH_REPLY,opt,opt,...'" log line,
// applying the profile's pull-filters exactly as apply_push_options does.
// ok is false if the line is not a push message.
func parsePushLine(line string, filters []pullFilter) (msg pushMessage, ok bool) {
	const marker = "Received control message: '"
	i := strings.Index(line, marker)
	if i < 0 {
		return msg, false
	}
	body := line[i+len(marker):]
	if j := strings.LastIndexByte(body, '\''); j >= 0 {
		body = body[:j]
	}
	opts := strings.Split(body, ",")
	switch opts[0] {
	case "PUSH_REPLY":
	case "PUSH_UPDATE":
		msg.update = true
	default:
		return msg, false
	}
	for _, opt := range opts[1:] {
		opt = strings.TrimLeft(opt, " \t\n\v\f\r")
		remove, optional := false, false
		if msg.update {
			if strings.HasPrefix(opt, "-") {
				remove, opt = true, opt[1:]
			}
			if strings.HasPrefix(opt, "?") {
				optional, opt = true, opt[1:]
			}
		}
		keep, accepted := filterPushed(filters, opt)
		if !accepted {
			if optional {
				continue
			}
			msg.rejected = true
			return msg, true
		}
		if !keep {
			continue
		}
		fields, err := parseLine(opt)
		if err != nil || len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "push-continuation":
			msg.more = len(fields) > 1 && fields[1] == "2"
		case "dns", "dhcp-option":
			if remove {
				msg.dns.touched = true
			} else {
				msg.dns.add(fields[0], fields[1:])
			}
		}
	}
	return msg, true
}
