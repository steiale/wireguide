package network

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// withJournal points the package at a scratch journal and stubs out the
// networksetup-driven restore for the duration of the test.
func withJournal(t *testing.T) (path string, restored *[2]map[string][]string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "data", DNSJournalFile)
	var got [2]map[string][]string
	origFn := restoreBaselineFn
	restoreBaselineFn = func(dns, search map[string][]string) { got = [2]map[string][]string{dns, search} }
	SetDNSJournalPath(path)
	t.Cleanup(func() {
		restoreBaselineFn = origFn
		SetDNSJournalPath("")
		dnsStateMu.Lock()
		dnsSavedDNS = make(map[string][]string)
		dnsSavedSearch = make(map[string][]string)
		dnsActiveIfaces = make(map[string]bool)
		dnsStateMu.Unlock()
	})
	return path, &got
}

func TestDNSJournalRoundTrip(t *testing.T) {
	path, restored := withJournal(t)

	wantDNS := map[string][]string{"Wi-Fi": {"192.168.1.1", "1.1.1.1"}, "Ethernet": nil}
	wantSearch := map[string][]string{"Wi-Fi": {"corp.example"}, "Ethernet": nil}
	dnsStateMu.Lock()
	dnsSavedDNS = wantDNS
	dnsSavedSearch = wantSearch
	writeDNSJournalLocked()
	dnsStateMu.Unlock()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("journal not written: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %v, want 0600", fi.Mode().Perm())
	}

	ok, err := RestoreDNSFromJournal()
	if err != nil || !ok {
		t.Fatalf("RestoreDNSFromJournal = %v, %v", ok, err)
	}
	if !reflect.DeepEqual(restored[0], wantDNS) || !reflect.DeepEqual(restored[1], wantSearch) {
		t.Fatalf("restored %v / %v, want %v / %v", restored[0], restored[1], wantDNS, wantSearch)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("journal not removed after restore: %v", err)
	}

	// No journal: no-op.
	if ok, err := RestoreDNSFromJournal(); ok || err != nil {
		t.Fatalf("second restore = %v, %v; want false, nil", ok, err)
	}
}

func TestDNSJournalRejectsInsecureFile(t *testing.T) {
	path, restored := withJournal(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"dns":{"Wi-Fi":["6.6.6.6"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, err := RestoreDNSFromJournal(); ok || err == nil {
		t.Fatalf("expected rejection of 0644 journal, got %v, %v", ok, err)
	}
	if restored[0] != nil {
		t.Fatalf("insecure journal was replayed: %v", restored[0])
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("insecure journal not removed")
	}
}

func TestClearDNSJournalOnlyWhenIdle(t *testing.T) {
	path, _ := withJournal(t)
	dnsStateMu.Lock()
	dnsSavedDNS = map[string][]string{"Wi-Fi": {"1.1.1.1"}}
	writeDNSJournalLocked()
	dnsActiveIfaces["utun9"] = true // a new override is active
	dnsStateMu.Unlock()

	clearDNSJournalIfIdle()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("journal removed while an override is still active: %v", err)
	}

	dnsStateMu.Lock()
	dnsActiveIfaces = make(map[string]bool)
	dnsSavedDNS = make(map[string][]string)
	dnsStateMu.Unlock()
	clearDNSJournalIfIdle()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("journal not removed when idle: %v", err)
	}
}
