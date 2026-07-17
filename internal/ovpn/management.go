package ovpn

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ChallengeKind identifies which OpenVPN challenge/response variant (if any)
// accompanies an auth prompt. See doc/management-notes.txt in the OpenVPN
// source (https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt)
// for the underlying CRV1/SCRV1 wire protocol this implements — used by
// RADIUS/LDAP-backed 2FA (e.g. a TOTP token requested as a separate step
// after the base password already succeeded).
type ChallengeKind string

const (
	ChallengeNone    ChallengeKind = ""        // plain username/password prompt
	ChallengeStatic  ChallengeKind = "static"  // SCRV1 — response collected alongside the password, in the same prompt
	ChallengeDynamic ChallengeKind = "dynamic" // CRV1 — response collected in a SEPARATE prompt, after the base password already succeeded
)

// AuthChallenge describes a challenge/response prompt the server is asking
// the client to answer.
type AuthChallenge struct {
	Kind ChallengeKind
	Text string // human-readable challenge/prompt text to show the user
	Echo bool   // true if the response should be shown as typed, not masked

	// StateID is CRV1 (dynamic)-only: an opaque token the server issued with
	// the challenge, which must be echoed back verbatim in the response.
	StateID string

	// Concat is SCRV1 (static)-only: true if the response should be
	// concatenated directly with the password as plain text (FORMAT=1); if
	// false, password and response are base64-encoded and combined with the
	// "SCRV1:" wire prefix (FORMAT=0, the more common case).
	Concat bool
}

// dynamicChallengeRe matches the CRV1 payload embedded in a
// ">PASSWORD:Verification Failed: 'Auth' ['CRV1:<flags>:<state_id>:<username_base64>:<challenge_text>']"
// line. The challenge text (last field) is free text and is not restricted
// from containing colons, so it's captured greedily up to the closing "']".
var dynamicChallengeRe = regexp.MustCompile(`CRV1:([^:]*):([^:]*):([^:]*):(.*)'\]`)

// staticChallengeRe matches the "SC:<flag>,<text>" suffix OpenVPN appends to
// a ">PASSWORD:Need 'Auth' username/password" line when the server config
// has "static-challenge" enabled.
var staticChallengeRe = regexp.MustCompile(`SC:(\d+),(.*)$`)

// parseDynamicChallenge extracts a CRV1 challenge from a "Verification
// Failed" payload (the part of the line after ">PASSWORD:"). Returns nil if
// the payload doesn't contain a CRV1 block (e.g. a plain wrong-password
// failure with no 2FA involved).
func parseDynamicChallenge(payload string) *AuthChallenge {
	m := dynamicChallengeRe.FindStringSubmatch(payload)
	if m == nil {
		return nil
	}
	flags, stateID, challengeText := m[1], m[2], m[4]
	return &AuthChallenge{
		Kind:    ChallengeDynamic,
		Text:    challengeText,
		Echo:    strings.Contains(flags, "E"),
		StateID: stateID,
	}
}

// parseStaticChallenge extracts an SCRV1 challenge from a "Need 'Auth'"
// payload. Returns nil if the payload has no "SC:" suffix (the common case
// — most servers don't use static-challenge).
func parseStaticChallenge(payload string) *AuthChallenge {
	m := staticChallengeRe.FindStringSubmatch(payload)
	if m == nil {
		return nil
	}
	flag, err := strconv.Atoi(m[1])
	if err != nil {
		return nil
	}
	return &AuthChallenge{
		Kind:   ChallengeStatic,
		Text:   m[2],
		Echo:   flag&0x1 != 0,
		Concat: flag&0x2 != 0,
	}
}

// mgmtClient is a thin client for the OpenVPN management interface over a Unix
// domain socket. OpenVPN, started with `management <sock> unix`, accepts
// newline-terminated commands and emits asynchronous notifications prefixed
// with ">" (e.g. >STATE:, >BYTECOUNT:, >PASSWORD:).
//
// See: https://openvpn.net/community-resources/management-interface/
type mgmtClient struct {
	conn net.Conn
	r    *bufio.Reader
}

// dialManagement connects to the OpenVPN management socket, retrying for up to
// 8 seconds while openvpn starts up and creates the socket.
func dialManagement(sockPath string) (*mgmtClient, error) {
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			return &mgmtClient{conn: conn, r: bufio.NewReader(conn)}, nil
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	return nil, fmt.Errorf("dial management socket %q: %w", sockPath, lastErr)
}

// send writes a single command followed by a newline.
func (c *mgmtClient) send(cmd string) error {
	_, err := c.conn.Write([]byte(cmd + "\n"))
	return err
}

// sendCredentials answers a >PASSWORD:Need 'Auth' prompt. OpenVPN expects the
// username first, then the password, each addressed to the "Auth" realm. Values
// are wrapped in double quotes; embedded quotes/backslashes are escaped per the
// management protocol.
func (c *mgmtClient) sendCredentials(username, password string) error {
	// Reject newlines — the management protocol is line-oriented and a \n inside
	// a quoted value terminates the command early, allowing injection.
	if strings.ContainsAny(username, "\r\n") || strings.ContainsAny(password, "\r\n") {
		return fmt.Errorf("credentials contain illegal newline characters")
	}
	if err := c.send(fmt.Sprintf("username \"Auth\" %s", mgmtQuote(username))); err != nil {
		return err
	}
	return c.send(fmt.Sprintf("password \"Auth\" %s", mgmtQuote(password)))
}

// mgmtQuote wraps s in double quotes and escapes backslashes and double quotes,
// as required by the OpenVPN management interface for values containing spaces.
func mgmtQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

// holdRelease tells a management-hold'd openvpn to proceed with connecting. We
// start openvpn with `management-hold` so it waits for us to attach before
// doing anything (avoids missing the first state/password notifications).
func (c *mgmtClient) holdRelease() error {
	return c.send("hold release")
}

// signalTerm asks openvpn to shut down cleanly (SIGTERM equivalent).
func (c *mgmtClient) signalTerm() error {
	return c.send("signal SIGTERM")
}

// readLoop reads management notifications until the connection closes, invoking
// the supplied callbacks. It enables real-time state and bytecount reporting on
// entry. onDone is always called exactly once when the loop exits.
//
//   - onState(state, localIP, remoteAddr string) — connection state, e.g.
//     "CONNECTING", "WAIT", "AUTH", "GET_CONFIG", "ASSIGN_IP", "CONNECTED",
//     "RECONNECTING", "EXITING". localIP is the tunnel-assigned client
//     address, populated only on CONNECTED. remoteAddr is "ip:port" of the
//     actual remote server OpenVPN is connected to right now (per
//     management-notes.txt: "(e) optional address of remote server, (f)
//     optional port of remote server" — shown for CONNECTED), also
//     populated only on CONNECTED. This is the CURRENT remote as OpenVPN
//     itself sees it — including after OpenVPN's own internal reconnect to
//     a different `remote` directive or a different round-robin DNS
//     answer — unlike a value resolved once up front at Connect time.
//   - onBytes(rx, tx int64)       — periodic byte counters.
//   - onAuthPrompt(sc *AuthChallenge) — the server is asking for username/
//     password. sc is non-nil if this specific prompt carries a static
//     (SCRV1) challenge suffix; nil for a plain prompt.
//   - onDynamicChallenge(ch *AuthChallenge) — the server rejected the
//     previous credentials with a CRV1 dynamic-challenge payload attached
//     (2FA required). ch is never nil when this is called. A plain
//     credential rejection with no CRV1 payload does NOT call this — it's
//     only logged.
//   - onDone()                    — the management connection ended.
func (c *mgmtClient) readLoop(
	onState func(state, localIP, remoteAddr string),
	onBytes func(rx, tx int64),
	onAuthPrompt func(sc *AuthChallenge),
	onDynamicChallenge func(ch *AuthChallenge),
	onDone func(),
) {
	defer onDone()

	// Ask openvpn to push state changes and a bytecount every second.
	_ = c.send("state on")
	_ = c.send("bytecount 1")

	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, ">STATE:"):
			// >STATE:<time>,<state>,<desc>,<localip>,<remoteip>,<remoteport>,<localaddr>,<localport>,<localipv6>
			payload := strings.TrimPrefix(line, ">STATE:")
			parts := strings.Split(payload, ",")
			if len(parts) >= 2 && onState != nil {
				localIP := ""
				if len(parts) >= 4 {
					localIP = parts[3]
				}
				remoteAddr := ""
				if len(parts) >= 6 && parts[4] != "" && parts[5] != "" {
					remoteAddr = net.JoinHostPort(parts[4], parts[5])
				}
				onState(parts[1], localIP, remoteAddr)
			}

		case strings.HasPrefix(line, ">BYTECOUNT:"):
			// >BYTECOUNT:<rx>,<tx>
			payload := strings.TrimPrefix(line, ">BYTECOUNT:")
			parts := strings.Split(payload, ",")
			if len(parts) >= 2 && onBytes != nil {
				rx, _ := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
				tx, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				onBytes(rx, tx)
			}

		case strings.HasPrefix(line, ">PASSWORD:"):
			// The auth-user-pass prompt:
			//   >PASSWORD:Need 'Auth' username/password
			//   >PASSWORD:Need 'Auth' username/password SC:<flag>,<text>   (static challenge)
			// Verification failures arrive as:
			//   >PASSWORD:Verification Failed: 'Auth'
			//   >PASSWORD:Verification Failed: 'Auth' ['CRV1:...']         (dynamic challenge)
			payload := strings.TrimPrefix(line, ">PASSWORD:")
			switch {
			case strings.HasPrefix(payload, "Need 'Auth'"):
				if onAuthPrompt != nil {
					onAuthPrompt(parseStaticChallenge(payload))
				}
			case strings.HasPrefix(payload, "Verification Failed"):
				if ch := parseDynamicChallenge(payload); ch != nil {
					if onDynamicChallenge != nil {
						onDynamicChallenge(ch)
					}
				} else {
					slog.Warn("ovpn: server rejected credentials", "detail", payload)
				}
			}

		case strings.HasPrefix(line, ">HOLD:"):
			// >HOLD:Waiting for hold release:<n> — sent whenever OpenVPN is
			// hibernating pending a "hold release" command. We start
			// openvpn with --management-hold so it waits for us to attach
			// before doing anything the FIRST time (avoids missing the
			// initial state/password notifications) — Connect() sends the
			// one-time initial release for that. But per management-notes.txt,
			// "the hold flag setting is persistent and will NOT be reset by
			// restarts" — so OpenVPN re-enters this exact hold state on
			// EVERY subsequent internal restart too (ping-restart, a
			// `remote` failover, the CRV1 auth-retry reconnect), and hangs
			// there forever unless something sends "hold release" again.
			// Without this case, the entire class of "OpenVPN reconnects
			// internally" scenarios this client relies on (CRV1's
			// auth-retry restart, the kill switch's remote-address
			// tracking across a `remote` failover) would silently stall on
			// every restart after the first.
			if err := c.holdRelease(); err != nil {
				slog.Warn("ovpn: hold release failed", "detail", line, "error", err)
			}
		}
	}
}

// close tears down the management connection.
func (c *mgmtClient) close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
