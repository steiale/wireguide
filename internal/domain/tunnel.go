package domain

// Protocol identifies which VPN backend a tunnel uses. WireGuide+ started as a
// WireGuard-only client; OpenVPN support was added later. Tunnels created before
// the protocol field existed have no value in their .meta.json — callers MUST
// treat the empty string as ProtocolWireGuard for backward compatibility.
type Protocol string

const (
	ProtocolWireGuard Protocol = "wireguard"
	ProtocolOpenVPN   Protocol = "openvpn"
)

// NormalizeProtocol returns p, defaulting an empty value (legacy meta files
// with no protocol field) to ProtocolWireGuard.
func NormalizeProtocol(p Protocol) Protocol {
	if p == "" {
		return ProtocolWireGuard
	}
	return p
}
