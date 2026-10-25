package ovpn

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ChallengeKind identifies which challenge/response variant (if any)
// accompanies an auth prompt (doc/management-notes.txt, CRV1/SCRV1).
type ChallengeKind string

const (
	ChallengeNone    ChallengeKind = ""        // plain username/password prompt
	ChallengeStatic  ChallengeKind = "static"  // SCRV1: response collected alongside the password
	ChallengeDynamic ChallengeKind = "dynamic" // CRV1: response collected after the base password succeeded
)

// AuthChallenge describes a challenge/response prompt the server is asking
// the client to answer.
type AuthChallenge struct {
	Kind ChallengeKind
	Text string // challenge text to show the user
	Echo bool   // show the response as typed instead of masked

	// StateID (CRV1 only) must be echoed back verbatim in the response.
	StateID string

	// Concat (SCRV1 only): append the response to the password as plain text
	// (FORMAT=1) instead of the base64 "SCRV1:" form.
	Concat bool

	// username (CRV1 only) is the username the server put in the challenge;
	// the response must be sent under it.
	username string
}

// User-facing messages for prompts LockPlus can't answer.
const (
	msgWebAuth       = "This server requires web/SSO authentication, which LockPlus doesn't support yet"
	msgPrivateKeyPw  = "This profile's private key is password-protected, which LockPlus doesn't support yet"
	msgProxyAuth     = "The HTTP proxy requires credentials; embed them in the profile as an inline <http-proxy-user-pass> block"
	msgUnknownPrompt = "OpenVPN asked for input LockPlus doesn't support"
)

// CRV1:<flags>:<state_id>:<username_base64>:<challenge_text>, text may
// contain colons.
var dynamicChallengeRe = regexp.MustCompile(`CRV1:([^:]*):([^:]*):([^:]*):(.*)'\]`)

// "SC:<flag>,<text>" suffix of a Need 'Auth' prompt (static-challenge).
var staticChallengeRe = regexp.MustCompile(`SC:(\d+),(.*)$`)

func parseDynamicChallenge(payload string) *AuthChallenge {
	m := dynamicChallengeRe.FindStringSubmatch(payload)
	if m == nil {
		return nil
	}
	ch := &AuthChallenge{
		Kind:    ChallengeDynamic,
		Text:    m[4],
		Echo:    strings.Contains(m[1], "E"),
		StateID: m[2],
	}
	if u, err := base64.StdEncoding.DecodeString(m[3]); err == nil {
		ch.username = string(u)
	}
	return ch
}

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

// mgmtHandler receives the notifications readLoop decodes.
type mgmtHandler interface {
	// state: localIP and remoteAddr ("ip:port") are only set on CONNECTED and
	// reflect the remote openvpn is actually using now.
	state(state, localIP, remoteAddr string)
	bytes(rx, tx int64)
	// authPrompt: sc is non-nil for a static-challenge prompt. May block
	// until the user answers.
	authPrompt(sc *AuthChallenge)
	// dynamicChallenge: the server answered the base credentials with CRV1.
	dynamicChallenge(ch *AuthChallenge)
	// failure: something the user must see. terminate means openvpn would
	// otherwise wait forever for input we can't give.
	failure(msg string, terminate bool)
}

// mgmtClient talks to openvpn's management interface over a unix socket.
type mgmtClient struct {
	conn net.Conn
	r    *bufio.Reader

	// mu serializes writes: the username and password lines of
	// sendCredentials must not interleave with another command.
	mu sync.Mutex

	timerMu   sync.Mutex
	holdTimer *time.Timer
	closed    bool
}

func newMgmtClient(conn net.Conn) *mgmtClient {
	return &mgmtClient{conn: conn, r: bufio.NewReader(conn)}
}

// dialManagement connects to the management socket, retrying for up to 8s
// while openvpn starts up.
func dialManagement(sockPath string) (*mgmtClient, error) {
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			return newMgmtClient(conn), nil
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	return nil, fmt.Errorf("dial management socket %q: %w", sockPath, lastErr)
}

func (c *mgmtClient) send(cmd string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeLocked(cmd)
}

// writeLocked has a deadline so a wedged openvpn that stops draining the
// socket can't block every other writer (Disconnect's SIGTERM) forever.
func (c *mgmtClient) writeLocked(cmd string) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	_, err := c.conn.Write([]byte(cmd + "\n"))
	return err
}

// sendCredentials answers a Need 'Auth' prompt.
func (c *mgmtClient) sendCredentials(username, password string) error {
	// The protocol is line-oriented; a newline would inject a command.
	if strings.ContainsAny(username, "\r\n") || strings.ContainsAny(password, "\r\n") {
		return fmt.Errorf("credentials contain illegal newline characters")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.writeLocked("username \"Auth\" " + mgmtQuote(username)); err != nil {
		return err
	}
	return c.writeLocked("password \"Auth\" " + mgmtQuote(password))
}

func mgmtQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

func (c *mgmtClient) signalTerm() error {
	return c.send("signal SIGTERM")
}

// releaseHold answers ">HOLD:Waiting for hold release:N". openvpn skips its
// own restart pause (socket_restart_pause sets sec=0) when a management hold
// was entered, so N is the connect-retry backoff we must honour ourselves;
// releasing at once turns a dead server or rejected inline password into a
// tight reconnect loop.
func (c *mgmtClient) releaseHold(wait time.Duration) {
	release := func() {
		if err := c.send("hold release"); err != nil {
			slog.Warn("ovpn: hold release failed", "error", err)
		}
	}
	if wait <= 0 {
		release()
		return
	}
	c.timerMu.Lock()
	defer c.timerMu.Unlock()
	if c.closed {
		return
	}
	if c.holdTimer != nil {
		c.holdTimer.Stop()
	}
	slog.Info("ovpn: restart pause before hold release", "seconds", wait.Seconds())
	c.holdTimer = time.AfterFunc(wait, release)
}

// Read deadlines. Before CONNECTED openvpn can be silent for up to its
// connect-timeout (120s default); once CONNECTED "bytecount 1" guarantees a
// line per second, so silence means a wedged process.
const (
	preConnectDeadline = 150 * time.Second
	connectedDeadline  = 30 * time.Second
)

// readLoop processes notifications until the connection closes or a read
// deadline expires.
func (c *mgmtClient) readLoop(h mgmtHandler) {
	_ = c.send("state on")
	_ = c.send("bytecount 1")

	readDeadline := preConnectDeadline
	for {
		if err := c.conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			return
		}
		line, err := c.r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		switch {
		case strings.HasPrefix(line, ">STATE:"):
			// >STATE:<time>,<state>,<desc>,<localip>,<remoteip>,<remoteport>,...
			parts := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
			if len(parts) < 2 {
				continue
			}
			localIP, remoteAddr := "", ""
			if len(parts) >= 4 {
				localIP = parts[3]
			}
			if len(parts) >= 6 && parts[4] != "" && parts[5] != "" {
				remoteAddr = net.JoinHostPort(parts[4], parts[5])
			}
			h.state(parts[1], localIP, remoteAddr)
			if parts[1] == "CONNECTED" {
				readDeadline = connectedDeadline
			} else {
				readDeadline = preConnectDeadline
			}

		case strings.HasPrefix(line, ">BYTECOUNT:"):
			parts := strings.Split(strings.TrimPrefix(line, ">BYTECOUNT:"), ",")
			if len(parts) >= 2 {
				rx, _ := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
				tx, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				h.bytes(rx, tx)
			}

		case strings.HasPrefix(line, ">PASSWORD:"):
			payload := strings.TrimPrefix(line, ">PASSWORD:")
			switch {
			case strings.HasPrefix(payload, "Need 'Auth'"):
				h.authPrompt(parseStaticChallenge(payload))
			case strings.HasPrefix(payload, "Need 'Private Key'"):
				h.failure(msgPrivateKeyPw, true)
			case strings.HasPrefix(payload, "Need 'HTTP Proxy'"):
				h.failure(msgProxyAuth, true)
			case strings.HasPrefix(payload, "Need "):
				h.failure(msgUnknownPrompt, true)
			case strings.HasPrefix(payload, "Verification Failed"):
				if ch := parseDynamicChallenge(payload); ch != nil {
					h.dynamicChallenge(ch)
				} else {
					h.failure(payload, false)
				}
			}

		case strings.HasPrefix(line, ">NEED-OK:"), strings.HasPrefix(line, ">NEED-STR:"):
			h.failure(msgUnknownPrompt, true)

		case strings.HasPrefix(line, ">INFOMSG:"):
			msg := strings.TrimPrefix(line, ">INFOMSG:")
			if strings.HasPrefix(msg, "WEB_AUTH:") || strings.HasPrefix(msg, "OPEN_URL:") || strings.HasPrefix(msg, "CR_TEXT:") {
				h.failure(msgWebAuth, true)
			}

		case strings.HasPrefix(line, ">FATAL:"):
			h.failure(strings.TrimPrefix(line, ">FATAL:"), false)

		case strings.HasPrefix(line, ">HOLD:"):
			// The hold flag persists across restarts, so this arrives on the
			// initial start (N=0) and before every internal restart.
			n := 0
			if i := strings.LastIndexByte(line, ':'); i >= 0 {
				n, _ = strconv.Atoi(strings.TrimSpace(line[i+1:]))
			}
			wait := time.Duration(n) * time.Second
			c.releaseHold(wait)
			// openvpn is silent while held; don't mistake that for a wedge.
			readDeadline = preConnectDeadline + wait
		}
	}
}

// close tears down the connection and cancels a pending hold release.
func (c *mgmtClient) close() error {
	c.timerMu.Lock()
	c.closed = true
	if c.holdTimer != nil {
		c.holdTimer.Stop()
	}
	c.timerMu.Unlock()
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
