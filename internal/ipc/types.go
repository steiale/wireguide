package ipc

import "github.com/steiale/wireguide/internal/domain"

// Empty is used for requests/responses with no payload.
type Empty struct{}

// PingResponse is returned from Helper.Ping.
type PingResponse struct {
	Version    string `json:"version"`     // IPC protocol version
	AppVersion string `json:"app_version"` // Application version (e.g. "0.1.5")
	PID        int    `json:"pid"`
	// BinaryPath is the absolute path of the running helper executable.
	// The GUI uses this to detect when the daemon is still the OLD
	// combined GUI binary running in --helper mode (i.e. the helper was
	// never reinstalled after a version upgrade). When the path is not the
	// expected /Library/PrivilegedHelperTools/...helper, the GUI forces
	// reinstall regardless of AppVersion match.
	BinaryPath string `json:"binary_path,omitempty"`
}

// ConnectRequest is the parameter for Tunnel.Connect.
//
// For WireGuard tunnels (the default), Config carries the parsed config and
// Protocol is empty or "wireguard". For OpenVPN tunnels, Protocol is "openvpn",
// Config is nil, TunnelName names the tunnel, and OVPNConfig carries the raw
// .ovpn file content (the helper writes it to its runtime dir and spawns
// openvpn). This keeps the WireGuard path byte-for-byte unchanged.
type ConnectRequest struct {
	Config        *domain.WireGuardConfig `json:"config"`
	AutoReconnect bool                    `json:"auto_reconnect"`

	Protocol   domain.Protocol `json:"protocol,omitempty"`
	TunnelName string          `json:"tunnel_name,omitempty"`
	OVPNConfig string          `json:"ovpn_config,omitempty"`
}

// AuthPromptEventPayload is broadcast (helper → GUI) when an OpenVPN tunnel is
// waiting for the user to enter credentials.
type AuthPromptEventPayload struct {
	TunnelName string `json:"tunnel_name"`
}

// SaveCredentialsRequest is the parameter for Ovpn.SaveCredentials. The helper
// persists username + base password (never the TOTP code) in the Keychain.
type SaveCredentialsRequest struct {
	TunnelName   string `json:"tunnel_name"`
	Username     string `json:"username"`
	BasePassword string `json:"base_password"`
}

// FeedCredentialsRequest is the parameter for Ovpn.FeedCredentials. FullPassword
// is basePassword + the 6-digit TOTP code, combined by the GUI just before the
// call so the helper forwards it verbatim to openvpn.
type FeedCredentialsRequest struct {
	TunnelName   string `json:"tunnel_name"`
	Username     string `json:"username"`
	FullPassword string `json:"full_password"`
}

// ConnectionStatus is the wire representation of the tunnel connection state.
// It is a direct alias of the domain type — there used to be a separate
// `ConnectionStatusDTO` here that drifted from the tunnel package's Status
// struct and caused a `handshake_age` vs `last_handshake` field-name bug in
// the frontend. Unifying on the domain type prevents that class of bug.
type ConnectionStatus = domain.ConnectionStatus

// KillSwitchRequest is the parameter for Firewall.SetKillSwitch.
type KillSwitchRequest struct {
	Enabled bool `json:"enabled"`
}

// DNSProtectionRequest is the parameter for Firewall.SetDNSProtection.
type DNSProtectionRequest struct {
	Enabled    bool     `json:"enabled"`
	DNSServers []string `json:"dns_servers,omitempty"`
}

// ReconnectStateDTO describes ongoing reconnection.
type ReconnectStateDTO struct {
	Reconnecting bool   `json:"reconnecting"`
	Attempt      int    `json:"attempt"`
	MaxAttempts  int    `json:"max_attempts"`
	NextRetry    string `json:"next_retry,omitempty"`
}

// LogEntry is a single structured log record forwarded from the helper
// to the GUI (and from the GUI to the frontend LogViewer). We keep it flat
// — no nested attrs — because the viewer just renders a one-line per entry.
type LogEntry struct {
	Time    string `json:"time"`    // RFC3339
	Level   string `json:"level"`   // "debug" | "info" | "warn" | "error"
	Source  string `json:"source"`  // "helper" | "gui"
	Message string `json:"message"` // human-readable text (already includes attrs)
}

// SetPinInterfaceRequest is the parameter for Network.SetPinInterface.
type SetPinInterfaceRequest struct {
	Enabled bool `json:"enabled"`
}

// SetHealthCheckRequest is the parameter for Monitor.SetHealthCheck.
type SetHealthCheckRequest struct {
	Enabled bool `json:"enabled"`
}

// SetLogLevelRequest is the parameter for Helper.SetLogLevel.
type SetLogLevelRequest struct {
	Level string `json:"level"` // "debug" | "info" | "warn" | "error"
}

// DisconnectRequest is the parameter for Tunnel.Disconnect.
// If TunnelName is empty, all tunnels are disconnected (backward compat).
type DisconnectRequest struct {
	TunnelName string `json:"tunnel_name,omitempty"`
}

// ActiveTunnelsResponse lists all currently active tunnel names.
type ActiveTunnelsResponse struct {
	Names []string `json:"names"`
}

// MultiStatusResponse carries status for every active tunnel plus an
// aggregate state. The frontend can iterate Tunnels for per-tunnel detail
// or use the top-level State for a single-tunnel-compatible view.
type MultiStatusResponse struct {
	State   domain.State        `json:"state"`
	Tunnels []ConnectionStatus  `json:"tunnels"`
}

// BoolResponse wraps a single bool.
type BoolResponse struct {
	Value bool `json:"value"`
}

// StringResponse wraps a single string.
type StringResponse struct {
	Value string `json:"value"`
}
