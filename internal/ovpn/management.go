package ovpn

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

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
//   - onState(state string)      — connection state, e.g. "CONNECTING",
//     "WAIT", "AUTH", "GET_CONFIG", "ASSIGN_IP", "CONNECTED", "RECONNECTING",
//     "EXITING".
//   - onBytes(rx, tx int64)       — periodic byte counters.
//   - onAuthPrompt()              — the server is asking for username/password.
//   - onDone()                    — the management connection ended.
func (c *mgmtClient) readLoop(
	onState func(state string),
	onBytes func(rx, tx int64),
	onAuthPrompt func(),
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
			// >STATE:<time>,<state>,<desc>,<localip>,<remoteip>,...
			payload := strings.TrimPrefix(line, ">STATE:")
			parts := strings.Split(payload, ",")
			if len(parts) >= 2 && onState != nil {
				onState(parts[1])
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
			// We only handle the auth-user-pass prompt:
			//   >PASSWORD:Need 'Auth' username/password
			// Verification failures arrive as:
			//   >PASSWORD:Verification Failed: 'Auth'
			payload := strings.TrimPrefix(line, ">PASSWORD:")
			if strings.HasPrefix(payload, "Need 'Auth'") && onAuthPrompt != nil {
				onAuthPrompt()
			} else if strings.HasPrefix(payload, "Verification Failed") {
				slog.Warn("ovpn: server rejected credentials", "detail", payload)
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
