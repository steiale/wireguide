package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestMain admits loopback httptest servers through the DownloadUpdate URL
// gate; tests that exercise the real gate swap isTrustedAssetURL back in.
func TestMain(m *testing.M) {
	assetURLTrusted = func(raw string) bool {
		if isTrustedAssetURL(raw) {
			return true
		}
		u, err := url.Parse(raw)
		return err == nil && u.Scheme == "http" && u.Hostname() == "127.0.0.1"
	}
	os.Exit(m.Run())
}

func withRealURLGate(t *testing.T) {
	t.Helper()
	prev := assetURLTrusted
	assetURLTrusted = isTrustedAssetURL
	t.Cleanup(func() { assetURLTrusted = prev })
}

func assertQuarantined(t *testing.T, path string) {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Getxattr(path, quarantineXattr, buf)
	if err != nil {
		t.Fatalf("getxattr %s: %v", quarantineXattr, err)
	}
	v := string(buf[:n])
	if !strings.HasPrefix(v, "0083;") || !strings.HasSuffix(v, ";LockPlus;") {
		t.Fatalf("unexpected quarantine value %q", v)
	}
}

func TestDownloadUpdate_RejectsUntrustedDownloadURL(t *testing.T) {
	withRealURLGate(t)
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	for _, u := range []string{
		srv.URL + "/asset.zip",
		"http://github.com/steiale/wireguide/releases/download/v9/asset.zip",
		"https://evil.example/asset.zip",
		"https://github.com.evil.example/asset.zip",
		"file:///etc/passwd",
	} {
		_, err := DownloadUpdate(&UpdateInfo{DownloadURL: u, AssetName: "asset.zip", AssetSize: minAssetSize})
		if err == nil || !strings.Contains(err.Error(), "untrusted download URL") {
			t.Errorf("%s: expected untrusted URL error, got %v", u, err)
		}
	}
	if hit {
		t.Error("untrusted URL was fetched")
	}
}

func TestDownloadUpdate_RejectsUntrustedSignatureURL(t *testing.T) {
	withRealURLGate(t)
	_, err := DownloadUpdate(&UpdateInfo{
		DownloadURL:  "https://github.com/steiale/wireguide/releases/download/v9/a.zip",
		SignatureURL: "https://evil.example/a.zip.sig",
		AssetName:    "a.zip",
		AssetSize:    minAssetSize,
	})
	if err == nil || !strings.Contains(err.Error(), "untrusted signature URL") {
		t.Fatalf("expected untrusted signature URL error, got %v", err)
	}
}

func TestDownloadUpdate_RejectsUntrustedRedirect(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect target was fetched")
	}))
	defer evil.Close()
	// Loopback is admitted by TestMain's gate, so redirect to a non-loopback
	// host name that resolves to the same server.
	target := strings.Replace(evil.URL, "127.0.0.1", "localhost", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+"/asset.zip", http.StatusFound)
	}))
	defer srv.Close()
	_, err := DownloadUpdate(&UpdateInfo{DownloadURL: srv.URL + "/asset.zip", AssetName: "asset.zip", AssetSize: minAssetSize})
	if err == nil || !strings.Contains(err.Error(), "untrusted URL") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

func TestQuarantineValueFormat(t *testing.T) {
	ts := time.Unix(0x6720abcd, 0)
	if got, want := quarantineValue(ts), "0083;6720abcd;LockPlus;"; got != want {
		t.Fatalf("quarantineValue = %q, want %q", got, want)
	}
}

func TestSetQuarantine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "update.zip")
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := setQuarantine(p, time.Now()); err != nil {
		t.Fatalf("setQuarantine: %v", err)
	}
	assertQuarantined(t, p)
}

// TestDownloadUpdate_SignatureFailLeavesNoFile ensures a download that
// fails signature verification never survives (quarantined or not).
func TestDownloadUpdate_SignatureFailLeavesNoFile(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	withTestPublicKey(t, pub)
	body := make([]byte, minAssetSize+10)
	h := sha256.Sum256(body)
	sig := ed25519.Sign(otherPriv, signedMessage("9.9.9", hex.EncodeToString(h[:])))
	srv := signedAssetServer(t, body, sig)
	defer srv.Close()
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "wireguide-update-*"))
	_, err := DownloadUpdate(&UpdateInfo{
		Version:      "9.9.9",
		DownloadURL:  srv.URL + "/asset.zip",
		SignatureURL: srv.URL + "/asset.zip.sig",
		AssetName:    "asset.zip",
		AssetSize:    int64(len(body)),
	})
	if err == nil {
		t.Fatal("expected signature failure")
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "wireguide-update-*"))
	if len(after) > len(before) {
		t.Fatalf("leftover download files: %v", after)
	}
}
