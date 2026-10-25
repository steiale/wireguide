package network

import (
	"os"
	"reflect"
	"testing"
)

func TestDNSHolderUnion(t *testing.T) {
	var s dnsHolderSet
	s.set("utun4", []string{"10.0.0.1", "corp.example"})
	s.set("ovpn-work", []string{"10.8.0.1", "10.0.0.1", "work.example"})

	servers, search := s.union()
	// Newest holder first: its resolver is primary.
	if want := []string{"10.8.0.1", "10.0.0.1"}; !reflect.DeepEqual(servers, want) {
		t.Fatalf("servers = %v, want %v", servers, want)
	}
	if want := []string{"work.example", "corp.example"}; !reflect.DeepEqual(search, want) {
		t.Fatalf("search = %v, want %v", search, want)
	}

	// Re-registering keeps position but replaces entries (OpenVPN PUSH_UPDATE).
	s.set("utun4", []string{"10.0.0.2"})
	if servers, _ := s.union(); !reflect.DeepEqual(servers, []string{"10.8.0.1", "10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("after update servers = %v", servers)
	}

	// Releasing one holder drops only its entries, not the shared one.
	if !s.remove("ovpn-work") {
		t.Fatal("remove reported missing holder")
	}
	servers, search = s.union()
	if !reflect.DeepEqual(servers, []string{"10.0.0.2"}) || search != nil {
		t.Fatalf("after release = %v / %v", servers, search)
	}
	if s.remove("ovpn-work") {
		t.Fatal("second remove should report false")
	}
	s.remove("utun4")
	if s.len() != 0 {
		t.Fatalf("len = %d after removing all", s.len())
	}
}

func TestSystemResolvers(t *testing.T) {
	path := t.TempDir() + "/resolv.conf"
	conf := "# comment\ndomain lan\nnameserver 192.168.1.1\nnameserver fe80::1%en0\nnameserver evil;pass\nnameserver 192.168.1.1\nsearch lan\n"
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	old := resolvConfPath
	resolvConfPath = path
	defer func() { resolvConfPath = old }()
	if got, want := SystemResolvers(), []string{"192.168.1.1", "fe80::1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SystemResolvers() = %v, want %v", got, want)
	}

	// No usable resolv.conf: fall back to the captured baseline.
	resolvConfPath = path + ".missing"
	dnsMu.Lock()
	dnsSavedDNS["Wi-Fi"] = []string{"9.9.9.9", "not-an-ip"}
	dnsMu.Unlock()
	defer func() {
		dnsMu.Lock()
		delete(dnsSavedDNS, "Wi-Fi")
		dnsMu.Unlock()
	}()
	if got, want := SystemResolvers(), []string{"9.9.9.9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fallback = %v, want %v", got, want)
	}
}
