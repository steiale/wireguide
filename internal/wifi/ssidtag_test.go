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
