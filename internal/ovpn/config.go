// Package ovpn implements OpenVPN backend support for LockPlus: parsing
// .ovpn config files, storing credentials in the macOS Keychain, driving the
// OpenVPN management interface, and supervising the openvpn subprocess.
//
// It uses only the Go standard library (plus the project's own domain types) —
// no CGo, no new external dependencies. The macOS `security` and `openvpn`
// CLIs are invoked via os/exec.
package ovpn

import (
	"fmt"
	"strings"
)

// OVPNConfig is the subset of an .ovpn file LockPlus cares about. The full
// file is still passed through verbatim to the openvpn binary — this struct is
// only used for display, validation, and deciding whether to prompt for
// credentials.
type OVPNConfig struct {
	Remote       string // first "remote <host> [port]" directive (host only)
	Proto        string // "udp" | "tcp" | "tcp-client" etc., empty if unspecified
	AuthUserPass bool   // true if "auth-user-pass" is present (credentials required)
}

// HasKeepaliveDirective reports whether the raw .ovpn content already
// configures OpenVPN's own dead-peer detection — directly via
// `ping`/`ping-restart`, or via `keepalive N M` (the shorthand OpenVPN
// expands to `ping N` + `ping-restart 2*M` itself, and what a server's
// PUSH_REPLY typically uses). Connect uses this to decide whether to inject
// a floor of its own: without ANY of these, a dropped peer never notices and
// the tunnel wedges forever with no self-healing, but a profile that already
// sets one deliberately (e.g. a longer restart window tuned for a
// high-latency link) must not be silently overridden.
func HasKeepaliveDirective(data []byte) bool {
	found := false
	forEachTopLevelDirective(data, func(fields []string) bool {
		switch fields[0] {
		case "ping", "ping-restart", "keepalive":
			found = true
		}
		return !found
	})
	return found
}

// HasMTUDirective reports whether the raw .ovpn content already tunes
// fragmentation behaviour via `mssfix`, `fragment`, `tun-mtu`, or `link-mtu`.
// Connect uses this to decide whether to inject its own `--mssfix` floor —
// see the CLI args comment there for why. Without any of these, OpenVPN's
// bundled 2.7 (unchanged from 2.6) defaults to a 1500 tun-mtu with no MSS clamp, so a
// full-size inner TCP segment (e.g. an RDP screen update) plus tunnel
// overhead routinely exceeds the path MTU and gets IP-fragmented — which
// then depends on middleboxes/firewalls handling fragments correctly to
// arrive at all (see the kill switch's own fragment-handling fix in
// internal/firewall/darwin.go for a concrete way that goes wrong locally).
func HasMTUDirective(data []byte) bool {
	found := false
	forEachTopLevelDirective(data, func(fields []string) bool {
		switch fields[0] {
		case "mssfix", "fragment", "tun-mtu", "link-mtu":
			found = true
		}
		return !found
	})
	return found
}

// defaultDataCiphers is OpenVPN 2.7's built-in --data-ciphers default.
const defaultDataCiphers = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

// LegacyDataCiphers returns a --data-ciphers value that restores OpenVPN
// 2.6's implicit behaviour for profiles that still set `cipher X` without
// `data-ciphers`: 2.6 appended X to the negotiable list, 2.7 silently ignores
// it, so a server that only speaks X (e.g. AES-256-CBC) stops connecting
// after the upgrade. Modern servers still negotiate GCM first. Returns "" when
// no shim is needed. BF-CBC is skipped because 2.7 still translates an
// explicit `cipher BF-CBC` itself; `none` is never re-enabled.
func LegacyDataCiphers(data []byte) string {
	var cipher string
	explicit := false
	forEachTopLevelDirective(data, func(fields []string) bool {
		switch fields[0] {
		case "data-ciphers", "ncp-ciphers":
			explicit = true
			return false
		case "cipher":
			if len(fields) > 1 {
				cipher = fields[1]
			}
		}
		return true
	})
	if explicit || cipher == "" || !isCipherName(cipher) {
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

// forEachTopLevelDirective calls fn with [name, args...] of every
// non-inline directive openvpn will apply, including those inside
// <connection> blocks, using the same tokenizer openvpn uses (see
// parse.go). Inline blobs (<ca>, <key>, ...) are skipped. Stops when fn
// returns false. A file that fails to parse yields no directives; callers
// run after ValidateOVPN, which reports the parse error.
func forEachTopLevelDirective(data []byte, fn func(fields []string) bool) {
	ds, err := parseConfig(data)
	if err != nil {
		return
	}
	walkDirectives(ds, func(d *directive) bool {
		if d.Inline {
			return true
		}
		return fn(append([]string{d.Name}, d.Args...))
	})
}

// ParseOVPN extracts the directives LockPlus needs for display and kill
// switch setup. It does not enforce the allowlist (ValidateOVPN does), but
// uses the same tokenizer, so it sees exactly what openvpn sees.
func ParseOVPN(data []byte) (*OVPNConfig, error) {
	ds, err := parseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("reading ovpn config: %w", err)
	}
	cfg := &OVPNConfig{}
	walkDirectives(ds, func(d *directive) bool {
		switch d.Name {
		case "remote":
			if cfg.Remote == "" && len(d.Args) >= 1 {
				if len(d.Args) >= 2 {
					host := d.Args[0]
					if strings.Contains(host, ":") {
						// IPv6 literal host with an explicit port — must be
						// bracketed, or "host:port" (e.g. "2001:db8::1:1194")
						// is ambiguous: net.SplitHostPort can't tell where
						// the host ends and the port begins, and the whole
						// unbracketed string can itself parse as a
						// (different, wrong) valid IPv6 address. Consumers
						// that need to split host from port again (kill
						// switch remote resolution, latency ping) rely on
						// this being unambiguous.
						host = "[" + host + "]"
					}
					cfg.Remote = host + ":" + d.Args[1]
				} else {
					cfg.Remote = d.Args[0]
				}
			}
		case "proto":
			if len(d.Args) >= 1 {
				cfg.Proto = strings.ToLower(d.Args[0])
			}
		case "auth-user-pass":
			// Inline credentials are used by openvpn directly; only the
			// bare form prompts.
			if !d.Inline {
				cfg.AuthUserPass = true
			}
		}
		return true
	})
	return cfg, nil
}

// maxOVPNSize bounds an imported profile. Real profiles are a few KB; even
// one with an inline PKCS#12 bundle is well under this.
const maxOVPNSize = 1 << 20

// ValidateOVPN decides whether an untrusted .ovpn may be handed to the
// root-run openvpn binary. It parses the file exactly as openvpn does
// (parse.go) and requires every directive — including those inside
// <connection> blocks and behind "setenv opt" — to be on the client-safe
// allowlist (allowlist.go). It must also name a remote and declare itself a
// client, so server configs are refused.
func ValidateOVPN(data []byte) error {
	if len(data) > maxOVPNSize {
		return fmt.Errorf("invalid .ovpn: file is larger than %d bytes", maxOVPNSize)
	}
	ds, err := parseConfig(data)
	if err != nil {
		return fmt.Errorf("invalid .ovpn: %w", err)
	}
	hasRemote, hasClient := false, false
	var verr error
	walkDirectives(ds, func(d *directive) bool {
		if err := checkDirective(d); err != nil {
			verr = fmt.Errorf("invalid .ovpn: line %d: %w", d.Line, err)
			return false
		}
		switch d.Name {
		case "remote":
			hasRemote = true
		case "client", "tls-client":
			hasClient = true
		}
		return true
	})
	if verr != nil {
		return verr
	}
	if !hasRemote {
		return fmt.Errorf("invalid .ovpn: no 'remote' directive found")
	}
	if !hasClient {
		return fmt.Errorf("invalid .ovpn: missing 'client' or 'tls-client' directive (is this a server config?)")
	}
	return nil
}
