// Package ovpn implements OpenVPN backend support for LockPlus: parsing
// .ovpn config files, storing credentials in the macOS Keychain, driving the
// OpenVPN management interface, and supervising the openvpn subprocess.
//
// It uses only the Go standard library (plus the project's own domain types) —
// no CGo, no new external dependencies. The macOS `security` and `openvpn`
// CLIs are invoked via os/exec.
package ovpn

import (
	"bufio"
	"bytes"
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

// normalizeDirective lowercases a config-file directive and strips an
// optional leading "--". OpenVPN itself accepts config-file directives
// either with or without the double-dash prefix normally only seen on the
// command line (see options.c) — it strips the prefix internally before
// matching, so a validator that only matches bare names (as this one
// previously did) can be bypassed entirely by prefixing a blocked directive
// with "--", e.g. "--up /tmp/evil.sh" instead of "up /tmp/evil.sh". Both
// forms must be checked identically here.
func normalizeDirective(field string) string {
	return strings.ToLower(strings.TrimPrefix(field, "--"))
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
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inInlineBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			if strings.HasPrefix(line, "</") {
				inInlineBlock = false
			} else if strings.ToLower(line) != "<connection>" {
				inInlineBlock = true
			}
			continue
		}
		if inInlineBlock {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch normalizeDirective(fields[0]) {
		case "ping", "ping-restart", "keepalive":
			return true
		}
	}
	return false
}

// HasMTUDirective reports whether the raw .ovpn content already tunes
// fragmentation behaviour via `mssfix`, `fragment`, `tun-mtu`, or `link-mtu`.
// Connect uses this to decide whether to inject its own `--mssfix` floor —
// see the CLI args comment there for why. Without any of these, OpenVPN's
// bundled 2.6 defaults to a 1500 tun-mtu with no MSS clamp, so a
// full-size inner TCP segment (e.g. an RDP screen update) plus tunnel
// overhead routinely exceeds the path MTU and gets IP-fragmented — which
// then depends on middleboxes/firewalls handling fragments correctly to
// arrive at all (see the kill switch's own fragment-handling fix in
// internal/firewall/darwin.go for a concrete way that goes wrong locally).
func HasMTUDirective(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inInlineBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			if strings.HasPrefix(line, "</") {
				inInlineBlock = false
			} else if strings.ToLower(line) != "<connection>" {
				inInlineBlock = true
			}
			continue
		}
		if inInlineBlock {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch normalizeDirective(fields[0]) {
		case "mssfix", "fragment", "tun-mtu", "link-mtu":
			return true
		}
	}
	return false
}

// ParseOVPN scans the lines of an .ovpn file for the directives LockPlus
// needs. It is intentionally lenient: unknown directives are ignored and the
// raw bytes are what actually gets handed to openvpn.
func ParseOVPN(data []byte) (*OVPNConfig, error) {
	cfg := &OVPNConfig{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// .ovpn files can carry large inline cert blobs; bump the line buffer so a
	// long base64 line doesn't trip bufio.ErrTooLong.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	inInlineBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// <connection>...</connection> blocks are valid OpenVPN constructs that
		// hold remote/proto directives — parse their contents normally.
		// All other <tag>...</tag> blocks are inline blob data (ca, cert, key,
		// tls-auth, etc.) and must be skipped entirely.
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			if strings.HasPrefix(line, "</") {
				inInlineBlock = false
			} else if strings.ToLower(line) != "<connection>" {
				inInlineBlock = true
			}
			continue
		}
		if inInlineBlock {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch normalizeDirective(fields[0]) {
		case "remote":
			if cfg.Remote == "" && len(fields) >= 2 {
				if len(fields) >= 3 {
					host := fields[1]
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
					cfg.Remote = host + ":" + fields[2]
				} else {
					cfg.Remote = fields[1]
				}
			}
		case "proto":
			if len(fields) >= 2 {
				cfg.Proto = strings.ToLower(fields[1])
			}
		case "auth-user-pass":
			cfg.AuthUserPass = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading ovpn config: %w", err)
	}
	return cfg, nil
}

// ValidateOVPN performs a minimal sanity check on an .ovpn file: it must name a
// remote and declare itself a client. Server configs (which lack these) are
// rejected so users don't accidentally import the wrong half of a profile.
func ValidateOVPN(data []byte) error {
	hasRemote := false
	hasClient := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	inInlineBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			if strings.HasPrefix(line, "</") {
				inInlineBlock = false
			} else if strings.ToLower(line) != "<connection>" {
				inInlineBlock = true
			}
			continue
		}
		if inInlineBlock {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		directive := normalizeDirective(fields[0])
		switch directive {
		case "remote":
			hasRemote = true
		case "client", "tls-client":
			hasClient = true
		// Reject script and plugin directives — the helper runs openvpn as root
		// with --script-security 1 (built-in ifconfig/route calls only, no
		// user-defined scripts — see manager.go), so these would be inert
		// anyway, but we also reject at import time so users get a clear
		// error rather than a silent no-op.
		//
		// "iproute" is included even though script-security 1 is meant to
		// exempt "built-in" networking calls: on iproute2-enabled openvpn
		// builds, --iproute substitutes an ARBITRARY binary in place of the
		// real ip/route call, which script-security 1 would still permit
		// since it can't tell the substitute apart from the real thing. Our
		// bundled macOS build isn't compiled with iproute2 support, so this
		// isn't currently exploitable, but blocking the directive at import
		// costs nothing and closes the gap if that ever changes.
		case "up", "down", "route-up", "route-pre-down",
			"tls-verify", "client-connect", "client-disconnect",
			"learn-address", "ipchange", "plugin", "iproute":
			return fmt.Errorf("invalid .ovpn: directive %q is not allowed (script/plugin execution is disabled)", directive)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading ovpn config: %w", err)
	}
	if !hasRemote {
		return fmt.Errorf("invalid .ovpn: no 'remote' directive found")
	}
	if !hasClient {
		return fmt.Errorf("invalid .ovpn: missing 'client' or 'tls-client' directive (is this a server config?)")
	}
	return nil
}
