// Package ovpn implements OpenVPN backend support for WireGuide+: parsing
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

// OVPNConfig is the subset of an .ovpn file WireGuide+ cares about. The full
// file is still passed through verbatim to the openvpn binary — this struct is
// only used for display, validation, and deciding whether to prompt for
// credentials.
type OVPNConfig struct {
	Remote       string // first "remote <host> [port]" directive (host only)
	Proto        string // "udp" | "tcp" | "tcp-client" etc., empty if unspecified
	AuthUserPass bool   // true if "auth-user-pass" is present (credentials required)
}

// ParseOVPN scans the lines of an .ovpn file for the directives WireGuide+
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
		switch strings.ToLower(fields[0]) {
		case "remote":
			if cfg.Remote == "" && len(fields) >= 2 {
				if len(fields) >= 3 {
					cfg.Remote = fields[1] + ":" + fields[2]
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
		directive := strings.ToLower(fields[0])
		switch directive {
		case "remote":
			hasRemote = true
		case "client", "tls-client":
			hasClient = true
		// Reject script and plugin directives — the helper runs openvpn as root
		// with --script-security 0, but we also reject at import time so users
		// get a clear error rather than a silent no-op.
		case "up", "down", "route-up", "route-pre-down",
			"tls-verify", "client-connect", "client-disconnect",
			"learn-address", "ipchange", "plugin":
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
