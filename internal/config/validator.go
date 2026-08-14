package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// hostnameRegex matches RFC 1035 hostnames (single-label or FQDN).
// Used to accept entries like `corp.example.com` in the `DNS =` field,
// which wg-quick treats as search domains rather than servers.
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// ValidationError represents a single validation issue.
type ValidationError struct {
	Field   string // e.g., "Interface.PrivateKey", "Peer[0].PublicKey"
	Message string // Human-readable error
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationResult holds all validation errors found.
type ValidationResult struct {
	Errors []ValidationError
}

func (r *ValidationResult) addError(field, message string) {
	r.Errors = append(r.Errors, ValidationError{Field: field, Message: message})
}

// IsValid returns true if no errors were found.
func (r *ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

// Validate checks a WireGuardConfig for correctness and returns all errors found.
func Validate(cfg *WireGuardConfig) *ValidationResult {
	result := &ValidationResult{}

	// Interface validation
	validateInterface(&cfg.Interface, result)

	// Must have at least one peer
	if len(cfg.Peers) == 0 {
		result.addError("Peer", "at least one [Peer] section is required")
	}

	// Peer validation
	for i := range cfg.Peers {
		validatePeer(&cfg.Peers[i], i, result)
	}

	return result
}

func validateInterface(iface *InterfaceConfig, result *ValidationResult) {
	// PrivateKey: required, Base64-encoded 32 bytes
	if iface.PrivateKey == "" {
		result.addError("Interface.PrivateKey", "PrivateKey is required")
	} else if !isValidWireGuardKey(iface.PrivateKey) {
		result.addError("Interface.PrivateKey", "invalid key format (must be Base64-encoded 32 bytes)")
	}

	// Address: required, valid CIDR
	if len(iface.Address) == 0 {
		result.addError("Interface.Address", "Address is required")
	} else {
		for _, addr := range iface.Address {
			if _, _, err := net.ParseCIDR(addr); err != nil {
				result.addError("Interface.Address", fmt.Sprintf("invalid CIDR format: %q", addr))
			}
		}
	}

	// DNS: optional. Each entry is either an IP address (DNS server) or a
	// hostname (search domain) — matching wg-quick's `DNS = 1.1.1.1, corp.example.com`
	// syntax. The network adapter splits them at apply time.
	for _, dns := range iface.DNS {
		if net.ParseIP(dns) == nil && !hostnameRegex.MatchString(dns) {
			result.addError("Interface.DNS", fmt.Sprintf("invalid DNS entry (not an IP or hostname): %q", dns))
		}
	}

	// MTU: optional, valid range
	if iface.MTU != 0 && (iface.MTU < 576 || iface.MTU > 65535) {
		result.addError("Interface.MTU", fmt.Sprintf("MTU must be between 576 and 65535, got %d", iface.MTU))
	}

	// ListenPort: optional, valid range
	if iface.ListenPort != 0 && (iface.ListenPort < 1 || iface.ListenPort > 65535) {
		result.addError("Interface.ListenPort", fmt.Sprintf("ListenPort must be between 1 and 65535, got %d", iface.ListenPort))
	}

	// Table: optional. wg-quick accepts "off", "auto", or a table number.
	// The network managers already parse this defensively (macOS only
	// string-compares against "off"; Linux parses to an int and falls back
	// to "auto" on anything unparseable) so a bad value can't reach a
	// command unsanitized — this rejects it up front instead of silently
	// falling back, since a typo'd table value silently becoming "auto" is
	// a confusing way to find out routing didn't do what the config asked.
	if t := iface.Table; t != "" && !strings.EqualFold(t, "off") && !strings.EqualFold(t, "auto") {
		if _, err := strconv.Atoi(t); err != nil {
			result.addError("Interface.Table", fmt.Sprintf("must be \"off\", \"auto\", or a table number, got %q", t))
		}
	}

	// FwMark: optional. wg-quick accepts "off" or a decimal/0x-prefixed hex
	// 32-bit value. Same defensive-parsing-downstream rationale as Table.
	if fw := iface.FwMark; fw != "" && !strings.EqualFold(fw, "off") {
		if _, err := parseDecimalOrHex(fw); err != nil {
			result.addError("Interface.FwMark", fmt.Sprintf("must be \"off\" or a decimal/hex number, got %q", fw))
		}
	}

	// ExtraKeys: unrecognized Interface directives preserved verbatim for
	// round-tripping (export). Reject embedded newlines — this config can
	// be re-exported and fed to a real wg-quick, which DOES interpret
	// PostUp/PreDown and other script directives; a value containing "\n"
	// could smuggle an extra directive line into that export.
	for k, v := range iface.ExtraKeys {
		if strings.ContainsAny(v, "\r\n") {
			result.addError("Interface.ExtraKeys", fmt.Sprintf("value for %q contains a newline", k))
		}
	}
}

// parseDecimalOrHex parses a decimal or "0x"-prefixed hexadecimal integer,
// matching wg-quick's accepted FwMark syntax.
func parseDecimalOrHex(s string) (int64, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseInt(s[2:], 16, 64)
	}
	return strconv.ParseInt(s, 10, 64)
}

func validatePeer(peer *PeerConfig, index int, result *ValidationResult) {
	prefix := fmt.Sprintf("Peer[%d]", index)

	// PublicKey: required
	if peer.PublicKey == "" {
		result.addError(prefix+".PublicKey", "PublicKey is required")
	} else if !isValidWireGuardKey(peer.PublicKey) {
		result.addError(prefix+".PublicKey", "invalid key format (must be Base64-encoded 32 bytes)")
	}

	// PresharedKey: optional, but if present must be valid
	if peer.PresharedKey != "" && !isValidWireGuardKey(peer.PresharedKey) {
		result.addError(prefix+".PresharedKey", "invalid key format (must be Base64-encoded 32 bytes)")
	}

	// Endpoint: optional, but if present must be host:port
	if peer.Endpoint != "" {
		if err := validateEndpoint(peer.Endpoint); err != nil {
			result.addError(prefix+".Endpoint", err.Error())
		}
	}

	// AllowedIPs: required, valid CIDR
	if len(peer.AllowedIPs) == 0 {
		result.addError(prefix+".AllowedIPs", "AllowedIPs is required")
	} else {
		for _, ip := range peer.AllowedIPs {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				result.addError(prefix+".AllowedIPs", fmt.Sprintf("invalid CIDR format: %q", ip))
			}
		}
	}

	// PersistentKeepalive: optional, valid range
	if peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
		result.addError(prefix+".PersistentKeepalive",
			fmt.Sprintf("must be between 0 and 65535, got %d", peer.PersistentKeepalive))
	}

	// ExtraKeys: same round-trip/export injection rationale as
	// Interface.ExtraKeys above.
	for k, v := range peer.ExtraKeys {
		if strings.ContainsAny(v, "\r\n") {
			result.addError(prefix+".ExtraKeys", fmt.Sprintf("value for %q contains a newline", k))
		}
	}
}

func isValidWireGuardKey(key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false
	}
	return len(decoded) == 32
}

func validateEndpoint(endpoint string) error {
	// Endpoint can be host:port or [ipv6]:port
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint format: %q (expected host:port)", endpoint)
	}
	if host == "" {
		return fmt.Errorf("endpoint host is empty")
	}
	// net.SplitHostPort only splits on the last colon — it doesn't validate
	// the host component at all, so a value like "1.2.3.4\nPostUp = evil"
	// previously passed straight through as long as SOMETHING after the
	// last colon parsed as a port number. This config is stored verbatim
	// and can later be re-exported (Serialize) for use with a real
	// wg-quick, which DOES execute PostUp/PreDown — so an embedded newline
	// here is a real script-injection vector one hop removed from this
	// app itself. Require the host to be a valid IP or hostname.
	if net.ParseIP(host) == nil && !hostnameRegex.MatchString(host) {
		return fmt.Errorf("invalid endpoint host (not an IP or hostname): %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid endpoint port: %q", portStr)
	}
	return nil
}

// ErrorMessages returns human-readable error strings for all validation errors.
func (r *ValidationResult) ErrorMessages() []string {
	msgs := make([]string, len(r.Errors))
	for i, e := range r.Errors {
		msgs[i] = e.Error()
	}
	return msgs
}
