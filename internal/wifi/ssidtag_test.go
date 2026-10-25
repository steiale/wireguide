package wifi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSIDTagKeyed(t *testing.T) {
	dir := t.TempDir()
	if err := InitSSIDTagKey(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ssidTagKeyFile)
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != ssidTagKeyLen {
		t.Fatalf("key file: %v %v", fi, err)
	}
	a := SSIDTag("HomeNet")
	if !strings.HasPrefix(a, "ssid#") || len(a) != len("ssid#")+12 || a != SSIDTag("HomeNet") || a == SSIDTag("Other") {
		t.Fatalf("tag %q", a)
	}
	if SSIDTag("") != "" {
		t.Fatal("empty SSID tagged")
	}

	// Stable across loads; never rewritten.
	if err := InitSSIDTagKey(dir); err != nil || SSIDTag("HomeNet") != a {
		t.Fatalf("reload changed tag: %v", err)
	}
	// A different install (key) tags differently.
	if err := InitSSIDTagKey(t.TempDir()); err != nil || SSIDTag("HomeNet") == a {
		t.Fatalf("tag not keyed per install: %v", err)
	}

	// Loose permissions are refused.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InitSSIDTagKey(dir); err == nil {
		t.Fatal("world-readable key accepted")
	}
}

// A truncated key file (ours, 0600) is replaced atomically and the new key
// persists; a symlink or loosely-permissioned short file is refused, never
// rewritten.
func TestSSIDTagKeyRepair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ssidTagKeyFile)
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InitSSIDTagKey(dir); err != nil {
		t.Fatalf("truncated key not repaired: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || fi.Size() != ssidTagKeyLen {
		t.Fatalf("repaired key file: %v %v", fi, err)
	}
	a := SSIDTag("HomeNet")
	if err := InitSSIDTagKey(dir); err != nil || SSIDTag("HomeNet") != a {
		t.Fatalf("repaired key not persistent: %v", err)
	}
	if left, _ := filepath.Glob(path + ".tmp-*"); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}

	// Short but world-readable: refused and left alone.
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InitSSIDTagKey(dir); err == nil {
		t.Fatal("insecure short key accepted")
	}
	if b, _ := os.ReadFile(path); string(b) != "short" {
		t.Fatal("insecure key file rewritten")
	}

	// A symlink (even to a valid key) is refused and not replaced.
	dir2 := t.TempDir()
	target := filepath.Join(dir2, "real")
	if err := os.WriteFile(target, make([]byte, ssidTagKeyLen), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir2, ssidTagKeyFile)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := InitSSIDTagKey(dir2); err == nil {
		t.Fatal("symlinked key accepted")
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink replaced")
	}
}
