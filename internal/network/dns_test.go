package network

import (
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
