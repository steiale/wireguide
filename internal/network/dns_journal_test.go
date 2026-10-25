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
		dnsMu.Lock()
		dnsSavedDNS = make(map[string][]string)
		dnsSavedSearch = make(map[string][]string)
		dnsHolders = dnsHolderSet{}
		dnsMu.Unlock()
	})
	return path, &got
}

func TestDNSJournalRoundTrip(t *testing.T) {
	path, restored := withJournal(t)

	wantDNS := map[string][]string{"Wi-Fi": {"192.168.1.1", "1.1.1.1"}, "Ethernet": nil}
	wantSearch := map[string][]string{"Wi-Fi": {"corp.example"}, "Ethernet": nil}
	dnsMu.Lock()
	dnsSavedDNS = wantDNS
	dnsSavedSearch = wantSearch
	writeDNSJournalLocked()
	dnsMu.Unlock()

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

// Releasing the last holder restores the baseline, then drops the journal.
func TestLastReleaseRestoresBaselineAndClearsJournal(t *testing.T) {
	path, restored := withJournal(t)
	baseline := map[string][]string{"Wi-Fi": {"192.168.1.1"}}
	dnsMu.Lock()
	dnsSavedDNS = baseline
	writeDNSJournalLocked()
	dnsHolders.set("utun9", []string{"10.0.0.1"})
	dnsMu.Unlock()

	if err := (&DarwinManager{}).RestoreDNS("other"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unknown holder release touched the journal: %v", err)
	}

	dnsMu.Lock()
	dnsHolders.remove("utun9")
	releaseOrReapplyLocked(nil)
	dnsMu.Unlock()
	if !reflect.DeepEqual(restored[0], baseline) {
		t.Fatalf("baseline not restored: %v", restored[0])
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("journal not removed after last release: %v", err)
	}
	if len(dnsSavedDNS) != 0 {
		t.Fatalf("in-memory baseline not reset: %v", dnsSavedDNS)
	}
}
