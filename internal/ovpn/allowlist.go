package ovpn

import (
	"fmt"
	"regexp"
	"strings"
)

// The helper runs openvpn as ROOT with the imported profile as --config, so
// every directive in an untrusted .ovpn executes with root privileges. A
// blocklist of "script" directives is not enough: log/status/writepid write
// arbitrary files, ca/cert/key/auth-user-pass/config read arbitrary files
// (and some send the contents to the server), engine/providers/pkcs11
// load shared libraries, user/group/chroot/cd/daemon change process state.
//
// So validation is an ALLOWLIST, built from OpenVPN 2.7.8's add_option
// (src/openvpn/options.c): client-side options that neither take a local
// filesystem path nor execute anything. Option names are matched exactly
// (openvpn's own matching is case-sensitive streq). Anything not listed is
// rejected with the directive name and line.

// dirCheck validates one directive's arguments. d.Inline is already known to
// be acceptable for the option when the check runs.
type dirCheck func(d *directive) error

type dirRule struct {
	inline   inlineMode
	validate dirCheck // nil: any arguments (none of them are paths)
}

type inlineMode int

const (
	inlineNever    inlineMode = iota // plain directive only
	inlineOnly                       // only as <name>...</name>; the file-path form is refused
	inlineOptional                   // either (argument is a value, not a path)
)

var (
	devNameRe  = regexp.MustCompile(`^u?tun[0-9]{0,3}$`)
	envNameRe  = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	errNoPaths = "file paths are not allowed; embed the content inline as <%s>...</%s>"
)

func maxArgs(n int) dirCheck {
	return func(d *directive) error {
		if len(d.Args) > n {
			return fmt.Errorf("too many arguments")
		}
		return nil
	}
}

var allowedDirectives map[string]dirRule

func init() {
	r := map[string]dirRule{}
	plain := func(names ...string) {
		for _, n := range names {
			r[n] = dirRule{}
		}
	}

	// Role / transport / remote selection.
	plain("client", "tls-client", "pull", "proto", "proto-force", "remote",
		"remote-random", "remote-random-hostname", "resolv-retry", "nobind",
		"bind", "local", "lport", "port", "rport", "float", "connect-retry",
		"connect-retry-max", "connect-timeout", "server-poll-timeout",
		"explicit-exit-notify", "sndbuf", "rcvbuf", "socket-flags", "fast-io",
		"http-proxy-option", "allow-pull-fqdn")
	// Persistence.
	plain("persist-key", "persist-tun", "persist-remote-ip", "persist-local-ip")
	// TLS / crypto policy (values only).
	plain("remote-cert-tls", "remote-cert-ku", "remote-cert-eku", "ns-cert-type",
		"verify-x509-name", "auth", "cipher", "data-ciphers",
		"data-ciphers-fallback", "ncp-ciphers", "tls-version-min",
		"tls-version-max", "tls-cipher", "tls-ciphersuites", "tls-groups",
		"ecdh-curve", "tls-cert-profile", "key-direction", "hand-window",
		"tran-window", "tls-timeout", "reneg-sec", "reneg-bytes", "reneg-pkts",
		"replay-window", "compat-mode")
	// Compression.
	plain("comp-lzo", "compress", "allow-compression")
	// Logging verbosity (no log FILE options).
	plain("verb", "mute", "mute-replay-warnings")
	// Auth behaviour (no credential files).
	plain("auth-nocache", "auth-retry", "static-challenge", "push-peer-info")
	// Routing / DNS / pushed-option filtering.
	plain("pull-filter", "route", "route-ipv6", "route-nopull", "route-gateway",
		"route-ipv6-gateway", "route-metric", "route-delay", "redirect-gateway",
		"redirect-private", "block-ipv6", "allow-recursive-routing",
		"dhcp-option", "dns", "topology")
	// MTU.
	plain("tun-mtu", "tun-mtu-extra", "tun-mtu-max", "mssfix", "fragment",
		"link-mtu", "mtu-disc")
	// Liveness.
	plain("keepalive", "ping", "ping-restart", "ping-exit", "ping-timer-rem",
		"inactive")
	// Misc no-ops / harmless.
	plain("tun-ipv6", "disable-occ", "disable-dco", "ignore-unknown-option")
	// Common in Linux-oriented profiles. Inert: nothing executable can pass
	// this allowlist, and Connect passes --script-security 1 after --config,
	// which overrides any value here.
	plain("script-security")
	// Windows-only options common in provider profiles. On macOS openvpn
	// either ignores them (route-method) or treats them as unknown, which is
	// fatal unless "ignore-unknown-option"/"setenv opt" marks them ignorable.
	// None of them is ever executed here.
	plain("route-method", "block-outside-dns", "register-dns", "ip-win32",
		"dhcp-renew", "dhcp-release", "dhcp-pre-release", "tap-sleep")

	// Key material: inline blocks only. 2.7 has no "[inline]" literal; a
	// non-inline argument is always a path openvpn opens as root.
	for _, n := range []string{"ca", "cert", "key", "extra-certs", "pkcs12",
		"crl-verify", "dh", "tls-auth", "tls-crypt", "tls-crypt-v2",
		"http-proxy-user-pass", "connection"} {
		r[n] = dirRule{inline: inlineOnly}
	}
	// Value-or-inline (the argument is a fingerprint, not a path).
	r["peer-fingerprint"] = dirRule{inline: inlineOptional}
	r["verify-hash"] = dirRule{inline: inlineOptional}

	// auth-user-pass: bare (prompt via management) or inline credentials.
	// Any argument is a file root would read and send to the server.
	r["auth-user-pass"] = dirRule{inline: inlineOptional, validate: func(d *directive) error {
		if !d.Inline && len(d.Args) > 0 {
			return fmt.Errorf("a credentials file is not allowed; use bare 'auth-user-pass' or an inline <auth-user-pass> block")
		}
		return nil
	}}
	r["dev"] = dirRule{validate: func(d *directive) error {
		if len(d.Args) != 1 || !devNameRe.MatchString(d.Args[0]) {
			return fmt.Errorf("only tun devices are supported")
		}
		return nil
	}}
	r["dev-type"] = dirRule{validate: func(d *directive) error {
		if len(d.Args) != 1 || d.Args[0] != "tun" {
			return fmt.Errorf("only dev-type tun is supported")
		}
		return nil
	}}
	// dns-updown runs a command as root; only the explicit no-op is allowed
	// (Connect passes --dns-updown disable after --config regardless).
	r["dns-updown"] = dirRule{validate: func(d *directive) error {
		if len(d.Args) != 1 || d.Args[0] != "disable" {
			return fmt.Errorf("only 'dns-updown disable' is allowed")
		}
		return nil
	}}
	// http-proxy SERVER PORT [auto|auto-nct|stdin [AUTH-METHOD]]; any other
	// third argument is a credentials file path.
	r["http-proxy"] = dirRule{validate: func(d *directive) error {
		if len(d.Args) <= 2 {
			return nil
		}
		switch d.Args[2] {
		case "auto", "auto-nct":
			return maxArgs(3)(d)
		case "stdin":
			return maxArgs(4)(d)
		}
		return fmt.Errorf("a proxy credentials file is not allowed; use an inline <http-proxy-user-pass> block")
	}}
	// socks-proxy SERVER [PORT [stdin]]; a third argument is otherwise a path.
	r["socks-proxy"] = dirRule{validate: func(d *directive) error {
		if len(d.Args) > 2 && d.Args[2] != "stdin" {
			return fmt.Errorf("a proxy credentials file is not allowed")
		}
		return maxArgs(3)(d)
	}}
	r["setenv"] = dirRule{validate: validateSetenv}
	r["setenv-safe"] = dirRule{validate: func(d *directive) error {
		if len(d.Args) < 1 || len(d.Args) > 2 || !envNameRe.MatchString(d.Args[0]) {
			return fmt.Errorf("invalid variable")
		}
		return nil
	}}
	allowedDirectives = r
}

// safeSetenvNames are the setenv variables openvpn interprets itself
// (options.c add_option "setenv") plus the ones provider profiles commonly
// carry. Arbitrary names are refused: the env set is exported to every
// program openvpn execs as root (route/ifconfig), so e.g. PATH or DYLD_*
// must never be settable from a profile.
var safeSetenvNames = map[string]bool{
	"FORWARD_COMPATIBLE":     true,
	"PUSH_PEER_INFO":         true,
	"REMOTE_RANDOM_HOSTNAME": true,
	"SERVER_POLL_TIMEOUT":    true,
	"CLIENT_CERT":            true,
}

// validateSetenv handles both setenv forms. "setenv opt X ..." is NOT an
// environment variable: add_option shifts p by two and processes X as a
// directive (only downgrading "unknown option" to a warning), so X must pass
// the allowlist like any other directive.
func validateSetenv(d *directive) error {
	if len(d.Args) >= 1 && d.Args[0] == "opt" {
		if len(d.Args) < 2 {
			return fmt.Errorf("'setenv opt' needs a directive")
		}
		inner := directive{Name: d.Args[1], Args: d.Args[2:], Line: d.Line}
		if err := checkDirective(&inner); err != nil {
			return fmt.Errorf("setenv opt: %w", err)
		}
		return nil
	}
	if len(d.Args) < 1 || len(d.Args) > 2 {
		return fmt.Errorf("invalid arguments")
	}
	name := d.Args[0]
	if !envNameRe.MatchString(name) {
		return fmt.Errorf("invalid variable name")
	}
	if safeSetenvNames[name] || strings.HasPrefix(name, "UV_") || strings.HasPrefix(name, "IV_") {
		return nil
	}
	return fmt.Errorf("variable %q is not allowed", name)
}

// checkDirective applies the allowlist to one directive. Errors name the
// directive (never its arguments, which may be secrets).
func checkDirective(d *directive) error {
	rule, ok := allowedDirectives[d.Name]
	if !ok {
		return fmt.Errorf("directive %q is not allowed", d.Name)
	}
	switch {
	case d.Inline && rule.inline == inlineNever:
		return fmt.Errorf("directive %q cannot be an inline <%s> block", d.Name, d.Name)
	case !d.Inline && rule.inline == inlineOnly:
		return fmt.Errorf("directive %q: "+errNoPaths, d.Name, d.Name, d.Name)
	}
	if rule.validate != nil {
		if err := rule.validate(d); err != nil {
			return fmt.Errorf("directive %q: %w", d.Name, err)
		}
	}
	return nil
}
