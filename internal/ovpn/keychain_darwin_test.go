//go:build darwin

package ovpn

import (
	"errors"
	"testing"
)

// testTunnelName is deliberately distinctive so this test can never collide
// with (or accidentally clobber) a real user's saved tunnel credentials.
const testTunnelName = "lockplus-keychain-native-test-tunnel"

func cleanupTestCredentials(t *testing.T) {
	t.Helper()
	if err := DeleteCredentials(testTunnelName); err != nil {
		t.Logf("cleanup: DeleteCredentials failed (may be harmless): %v", err)
	}
}

func TestNativeKeychain_RoundTrip(t *testing.T) {
	cleanupTestCredentials(t)
	defer cleanupTestCredentials(t)

	if err := StoreCredentials(testTunnelName, "alice", "s3cret\npassword\twith\x00odd bytes"); err != nil {
		t.Fatalf("StoreCredentials: %v", err)
	}

	creds, err := LoadCredentials(testTunnelName)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if creds.Username != "alice" {
		t.Errorf("Username = %q, want %q", creds.Username, "alice")
	}
	if creds.BasePassword != "s3cret\npassword\twith\x00odd bytes" {
		t.Errorf("BasePassword = %q, want the original odd-byte value back exactly", creds.BasePassword)
	}
}

func TestNativeKeychain_Update(t *testing.T) {
	cleanupTestCredentials(t)
	defer cleanupTestCredentials(t)

	if err := StoreCredentials(testTunnelName, "alice", "first-password"); err != nil {
		t.Fatalf("StoreCredentials (first): %v", err)
	}
	if err := StoreCredentials(testTunnelName, "bob", "second-password"); err != nil {
		t.Fatalf("StoreCredentials (update): %v", err)
	}

	creds, err := LoadCredentials(testTunnelName)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if creds.Username != "bob" || creds.BasePassword != "second-password" {
		t.Errorf("got (%q, %q), want (%q, %q) — SecItemUpdate should have overwritten the first item, not created a duplicate",
			creds.Username, creds.BasePassword, "bob", "second-password")
	}
}

func TestNativeKeychain_NotFound(t *testing.T) {
	cleanupTestCredentials(t)

	_, err := LoadCredentials(testTunnelName)
	if !errors.Is(err, ErrCredentialsNotFound) {
		t.Fatalf("LoadCredentials on a never-stored tunnel: got err=%v, want ErrCredentialsNotFound", err)
	}
}

func TestNativeKeychain_DeleteIsIdempotent(t *testing.T) {
	cleanupTestCredentials(t)

	if err := DeleteCredentials(testTunnelName); err != nil {
		t.Fatalf("DeleteCredentials on an already-absent item should succeed (no-op), got: %v", err)
	}
}

// Note: a cross-check via the `security` CLI (a different process/code
// identity than the one that created the item) was deliberately NOT added
// here — accessing another app's Keychain item triggers a blocking macOS
// GUI authorization prompt ("security wants to access a keychain item
// created by lockplus..., allow?"), which hangs forever in a non-interactive
// test run with nobody able to click "Allow". That the `security` CLI can
// no longer read this item without explicit user approval is in fact the
// ACL hardening this rewrite adds working as intended (the old CLI-created
// items had no such restriction). The accessibility attribute itself
// (kSecAttrAccessibleWhenUnlockedThisDeviceOnly) is set directly in
// keychain_darwin.m and is straightforward to confirm by reading that file.
