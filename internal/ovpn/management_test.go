package ovpn

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a mgmtHandler that logs every callback as a string.
type recorder struct {
	mu     sync.Mutex
	events []string
	auth   chan *AuthChallenge
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	r.events = append(r.events, s)
	r.mu.Unlock()
}
func (r *recorder) state(s, ip, remote string) { r.add("state " + s + " " + ip + " " + remote) }
func (r *recorder) bytes(rx, tx int64)         { r.add(fmt.Sprintf("bytes %d %d", rx, tx)) }
func (r *recorder) authPrompt(sc *AuthChallenge) {
	r.add(fmt.Sprintf("auth %v", sc != nil))
	r.auth <- sc
}
func (r *recorder) dynamicChallenge(ch *AuthChallenge) {
	r.add("crv1 " + ch.StateID + " " + ch.username + " " + ch.Text)
	r.auth <- ch
}
func (r *recorder) authFailed(msg string) { r.add("authfail " + msg) }
func (r *recorder) failure(msg string, terminate bool) {
	r.add(fmt.Sprintf("fail %v %s", terminate, msg))
}

func (r *recorder) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, e := range r.events {
			if e == want {
				r.mu.Unlock()
				return
			}
		}
		r.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t.Fatalf("event %q not seen; got %q", want, r.events)
}

// fakeOpenVPN is the openvpn side of a net.Pipe management connection.
type fakeOpenVPN struct {
	conn  net.Conn
	lines chan string
}

func newFake(t *testing.T) (*fakeOpenVPN, *mgmtClient) {
	a, b := net.Pipe()
	f := &fakeOpenVPN{conn: a, lines: make(chan string, 64)}
	go func() {
		s := bufio.NewScanner(a)
		for s.Scan() {
			f.lines <- s.Text()
		}
		close(f.lines)
	}()
	c := newMgmtClient(b)
	t.Cleanup(func() { c.close(); a.Close() })
	return f, c
}

func (f *fakeOpenVPN) say(t *testing.T, line string) {
	t.Helper()
	if _, err := f.conn.Write([]byte(line + "\r\n")); err != nil {
		t.Fatalf("write %q: %v", line, err)
	}
}

func (f *fakeOpenVPN) expect(t *testing.T, want string, within time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	select {
	case got := <-f.lines:
		if got != want {
			t.Fatalf("command %q, want %q", got, want)
		}
	case <-time.After(within):
		t.Fatalf("no %q within %v", want, within)
	}
	return time.Since(start)
}

func (f *fakeOpenVPN) expectNone(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case got, ok := <-f.lines:
		if ok {
			t.Fatalf("unexpected command %q", got)
		}
	case <-time.After(within):
	}
}

func TestMgmtProtocol(t *testing.T) {
	f, c := newFake(t)
	r := &recorder{auth: make(chan *AuthChallenge, 4)}
	done := make(chan struct{})
	go func() { c.readLoop(r); close(done) }()

	f.expect(t, "state on", time.Second)
	f.expect(t, "bytecount 1", time.Second)

	// Initial hold: released at once.
	f.say(t, ">HOLD:Waiting for hold release:0")
	f.expect(t, "hold release", time.Second)

	f.say(t, ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,,")
	r.waitFor(t, "state CONNECTED 10.8.0.2 203.0.113.5:1194")
	f.say(t, ">BYTECOUNT:123,456")
	r.waitFor(t, "bytes 123 456")

	// Restart hold with backoff: released only after N seconds.
	f.say(t, ">HOLD:Waiting for hold release:1")
	f.expectNone(t, 700*time.Millisecond)
	f.expect(t, "hold release", time.Second)

	// Plain auth prompt and static challenge.
	f.say(t, ">PASSWORD:Need 'Auth' username/password")
	if sc := <-r.auth; sc != nil {
		t.Errorf("plain prompt carried a challenge: %+v", sc)
	}
	f.say(t, ">PASSWORD:Need 'Auth' username/password SC:3,Enter PIN")
	if sc := <-r.auth; sc == nil || sc.Kind != ChallengeStatic || sc.Text != "Enter PIN" || !sc.Echo || !sc.Concat {
		t.Errorf("static challenge = %+v", sc)
	}

	// CRV1 carries its own username.
	user := base64.StdEncoding.EncodeToString([]byte("alice@corp"))
	f.say(t, ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:"+user+":Enter: your token']")
	ch := <-r.auth
	if ch.Kind != ChallengeDynamic || ch.username != "alice@corp" || ch.Text != "Enter: your token" || !ch.Echo {
		t.Errorf("CRV1 = %+v", ch)
	}

	f.say(t, ">PASSWORD:Verification Failed: 'Auth'")
	r.waitFor(t, "authfail Verification Failed: 'Auth'")
	f.say(t, ">PASSWORD:Need 'Private Key' password")
	r.waitFor(t, "fail true "+msgPrivateKeyPw)
	f.say(t, ">PASSWORD:Need 'HTTP Proxy' username/password")
	r.waitFor(t, "fail true "+msgProxyAuth)
	f.say(t, ">INFOMSG:WEB_AUTH::https://sso.example/login")
	r.waitFor(t, "fail true "+msgWebAuth)
	f.say(t, ">INFOMSG:CR_TEXT:E,R:Enter OTP")
	f.say(t, ">FATAL:Cannot open TUN/TAP dev")
	r.waitFor(t, "fail false Cannot open TUN/TAP dev")

	f.conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not return on close")
	}
}

func TestMgmtHoldCancelledOnClose(t *testing.T) {
	f, c := newFake(t)
	r := &recorder{auth: make(chan *AuthChallenge, 1)}
	go c.readLoop(r)
	f.expect(t, "state on", time.Second)
	f.expect(t, "bytecount 1", time.Second)
	f.say(t, ">HOLD:Waiting for hold release:1")
	time.Sleep(50 * time.Millisecond)
	c.close()
	c.timerMu.Lock()
	defer c.timerMu.Unlock()
	if c.holdTimer == nil || c.holdTimer.Stop() {
		t.Error("pending hold release not cancelled by close")
	}
}

func TestSendCredentialsQuoting(t *testing.T) {
	f, c := newFake(t)
	go func() { _ = c.sendCredentials(`a"b`, `p\w`) }()
	f.expect(t, `username "Auth" "a\"b"`, time.Second)
	f.expect(t, `password "Auth" "p\\w"`, time.Second)
	if err := c.sendCredentials("u", "p\nsignal SIGTERM"); err == nil || !strings.Contains(err.Error(), "newline") {
		t.Errorf("newline not rejected: %v", err)
	}
}
