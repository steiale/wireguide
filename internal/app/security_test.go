package app

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steiale/wireguide/internal/storage"
	"github.com/steiale/wireguide/internal/update"
)

func TestPathGrants_ReadFileRequiresGrant(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.conf")
	if err := os.WriteFile(p, []byte("[Interface]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &TunnelService{}

	if _, err := s.ReadFile(p); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("ungranted ReadFile: want not-authorized, got %v", err)
	}

	GrantPaths(s, []string{p})
	if got, err := s.ReadFile(p); err != nil || got != "[Interface]\n" {
		t.Fatalf("granted ReadFile: got %q, %v", got, err)
	}
	// Single use.
	if _, err := s.ReadFile(p); err == nil {
		t.Fatal("grant should be consumed after one use")
	}
}

func TestPathGrants_CleanedAndAbsoluteOnly(t *testing.T) {
	s := &TunnelService{}
	s.grantPaths([]string{"relative.conf", "", "/x/y/../z.conf"})
	if err := s.consumePath("relative.conf"); err == nil {
		t.Error("relative path must never be granted")
	}
	if err := s.consumePath("/x/z.conf"); err != nil {
		t.Errorf("cleaned path should match: %v", err)
	}
}

func TestPathGrants_Expire(t *testing.T) {
	s := &TunnelService{}
	s.grantPaths([]string{"/a.conf"})
	s.pathGrantsMu.Lock()
	s.pathGrants["/a.conf"] = time.Now().Add(-time.Second)
	s.pathGrantsMu.Unlock()
	if err := s.consumePath("/a.conf"); err == nil {
		t.Fatal("expired grant must be rejected")
	}
}

func TestPathGrants_OtherBindingsGated(t *testing.T) {
	s := &TunnelService{}
	if _, err := s.ImportZip("/etc/passwd"); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("ImportZip: %v", err)
	}
	if err := s.ImportQRFromPath("/etc/passwd", "x"); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("ImportQRFromPath: %v", err)
	}
	res := s.ImportFoundConfigs([]string{"/etc/passwd"})
	if len(res) != 1 || !strings.Contains(res[0].Error, "not authorized") {
		t.Errorf("ImportFoundConfigs: %+v", res)
	}
}

func TestImportZip_EntryCap(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	total := maxZipEntries + 7
	for i := 0; i < total; i++ {
		w, err := zw.Create(fmt.Sprintf("t%d.conf", i))
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("not a config"))
	}
	zw.Close()

	s := &TunnelService{tunnelStore: storage.NewTunnelStore(t.TempDir())}
	res, err := s.ImportZipData(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != maxZipEntries+1 {
		t.Fatalf("got %d results, want %d", len(res), maxZipEntries+1)
	}
	last := res[len(res)-1]
	if !strings.Contains(last.Error, "7 skipped") {
		t.Fatalf("missing cap summary, got %+v", last)
	}
}

func TestWritePrivateFile_FixesPermsOnExistingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "export.conf")
	if err := os.WriteFile(p, []byte("old old old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(p, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("perm = %o, want 600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(p); string(b) != "secret" {
		t.Errorf("content = %q", b)
	}
}

func TestWritePrivateFile_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(link, []byte("secret")); err == nil {
		t.Fatal("expected error writing through symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("symlink target modified: %q", b)
	}
}

func TestRunUpdate_UsesOnlyCachedInfo(t *testing.T) {
	s := &TunnelService{}
	if err := s.RunUpdate("9.9.9"); err == nil || !strings.Contains(err.Error(), "check for updates first") {
		t.Fatalf("no cache: got %v", err)
	}
	s.lastUpdate = &update.UpdateInfo{Available: true, Version: "1.2.3", SignatureVerified: true}
	if err := s.RunUpdate("9.9.9"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("version mismatch: got %v", err)
	}
	info, err := s.cachedUpdate("1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if info.SignatureVerified || info == s.lastUpdate {
		t.Fatal("cachedUpdate must return a fresh copy with verification flags cleared")
	}
}
