package storage

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/steiale/wireguide/internal/domain"
)

func TestRename(t *testing.T) {
	dir := t.TempDir()
	s := NewTunnelStore(dir)
	cfg := testConfig()
	cfg.Name = "Work"
	if err := s.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveMeta("Work", &TunnelMeta{Notes: "n"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveOVPN("Other", "client\n"); err != nil {
		t.Fatal(err)
	}

	// Case-only rename must work on case-insensitive APFS.
	if err := s.Rename("Work", "work"); err != nil {
		t.Fatalf("case-only rename: %v", err)
	}
	names, _ := s.List()
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"Other", "work"}) {
		t.Errorf("List after case rename = %q", names)
	}
	if m, _ := s.LoadMeta("work"); m.Notes != "n" {
		t.Errorf("meta not carried over: %+v", m)
	}

	if err := s.Rename("work", "Other"); err == nil {
		t.Error("rename onto an existing tunnel accepted")
	}
	if err := s.Rename("missing", "x"); err == nil {
		t.Error("rename of a missing tunnel accepted")
	}
	if err := s.Rename("../../etc/passwd", "x"); err == nil {
		t.Error("traversal accepted")
	}
	if err := s.Rename("Other", "Renamed"); err != nil {
		t.Fatal(err)
	}
	if !s.IsOVPN("Renamed") || s.Exists("Other") {
		t.Error(".ovpn not renamed")
	}
}

func TestLoadMetaInfersProtocol(t *testing.T) {
	s := NewTunnelStore(t.TempDir())
	if err := s.Save(testConfig()); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveOVPN("ov", "client\n"); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]domain.Protocol{"test-vpn": domain.ProtocolWireGuard, "ov": domain.ProtocolOpenVPN} {
		m, err := s.LoadMeta(name)
		if err != nil || m.Protocol != want {
			t.Errorf("%s: %+v %v, want %s", name, m, err, want)
		}
	}
	// Stale meta claiming WireGuard loses to the .ovpn file.
	if err := s.SaveMeta("ov", &TunnelMeta{Protocol: domain.ProtocolWireGuard, AutoReconnect: true}); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.LoadMeta("ov"); m.Protocol != domain.ProtocolOpenVPN || !m.AutoReconnect {
		t.Errorf("stale meta: %+v", m)
	}
}

func TestMigrateTunnels(t *testing.T) {
	legacy, dst := t.TempDir(), t.TempDir()
	write := func(dir, name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(legacy, "a.conf", "legacy-a")
	write(legacy, "b.ovpn", "legacy-b")
	write(legacy, ".wireguide-123.tmp", "partial")
	write(legacy, "b.meta.json", "{}")
	// Interrupted earlier run: a.conf already copied and edited since.
	write(dst, "a.conf", "edited-a")

	migrateTunnels(legacy, dst)

	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(dst, name))
		return string(b)
	}
	if read("a.conf") != "edited-a" {
		t.Error("existing file overwritten")
	}
	if read("b.ovpn") != "legacy-b" || read("b.meta.json") != "{}" {
		t.Error("missing files not copied into a non-empty dir")
	}
	if _, err := os.Stat(filepath.Join(dst, ".wireguide-123.tmp")); err == nil {
		t.Error(".tmp file copied")
	}
	if fi, err := os.Stat(filepath.Join(dst, "b.ovpn")); err != nil || fi.Mode().Perm() != 0600 {
		t.Errorf("perm: %v %v", fi, err)
	}

	// After a clean pass, deleted tunnels are not resurrected.
	os.Remove(filepath.Join(dst, "b.ovpn"))
	migrateTunnels(legacy, dst)
	if _, err := os.Stat(filepath.Join(dst, "b.ovpn")); err == nil {
		t.Error("deleted tunnel resurrected after completed migration")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	for _, body := range []string{"one", "two"} {
		if err := WriteFileAtomic(p, []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(b) != "two" || fi.Mode().Perm() != 0600 {
		t.Errorf("content %q perm %v", b, fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %d entries", len(entries))
	}
}
