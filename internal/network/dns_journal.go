package network

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
)

// DNSJournalFile is the file name (inside the helper's data dir) of the
// on-disk journal of the user's original DNS settings.
//
// Whenever SetDNS (WireGuard and OpenVPN both route through it) captures the
// pre-VPN baseline, the baseline is also written here. It is removed once the
// baseline has been restored. If the helper dies without restoring (SIGKILL,
// crash, launchd timeout), the next helper process replays it at startup via
// RestoreDNSFromJournal, so dead VPN resolvers never outlive the helper.
const DNSJournalFile = "dns-journal.json"

// dnsJournalPath is guarded by dnsMu. Empty disables journaling.
var dnsJournalPath string

// restoreBaselineFn is the function used to push a baseline back to the
// system. A variable so tests can stub out networksetup.
var restoreBaselineFn = restoreDNSBaseline

type dnsJournal struct {
	DNS    map[string][]string `json:"dns"`
	Search map[string][]string `json:"search"`
}

// SetDNSJournalPath sets where the DNS baseline journal is kept. The helper
// calls this once at startup with a path under its root-owned data dir.
func SetDNSJournalPath(path string) {
	dnsMu.Lock()
	dnsJournalPath = path
	dnsMu.Unlock()
}

// writeDNSJournalLocked persists the current in-memory baseline. Caller must
// hold dnsMu. Written atomically (temp file + rename), mode 0600.
func writeDNSJournalLocked() {
	if dnsJournalPath == "" {
		return
	}
	data, err := json.Marshal(dnsJournal{DNS: dnsSavedDNS, Search: dnsSavedSearch})
	if err != nil {
		slog.Warn("DNS journal: marshal failed", "error", err)
		return
	}
	if err := writeFileAtomic0600(dnsJournalPath, data); err != nil {
		slog.Warn("DNS journal: write failed", "path", dnsJournalPath, "error", err)
	}
}

// removeDNSJournalLocked deletes the journal. Caller must hold dnsMu.
func removeDNSJournalLocked() {
	if dnsJournalPath == "" {
		return
	}
	if err := os.Remove(dnsJournalPath); err != nil && !os.IsNotExist(err) {
		slog.Warn("DNS journal: remove failed", "path", dnsJournalPath, "error", err)
	}
}

func writeFileAtomic0600(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %v %v %v", tmp, werr, serr, cerr)
	}
	return os.Rename(tmp, path)
}

// loadDNSJournal reads and validates the journal. It refuses files not owned
// by the current (root) user or accessible by group/other, so a tampered
// journal can't steer root's networksetup calls.
func loadDNSJournal(path string) (*dnsJournal, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("%s owned by uid %d, expected %d", path, st.Uid, os.Geteuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has insecure mode %v", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var j dnsJournal
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &j, nil
}

// RestoreDNSFromJournal replays a journal left behind by a previous helper
// process and removes it. Must be called at helper startup, before any tunnel
// is connected. Returns true if a journal was found and replayed.
func RestoreDNSFromJournal() (bool, error) {
	dnsMu.Lock()
	path := dnsJournalPath
	dnsMu.Unlock()
	if path == "" {
		return false, nil
	}
	j, err := loadDNSJournal(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		_ = os.Remove(path) // untrusted or corrupt: never replay it
		return false, err
	}
	restoreBaselineFn(j.DNS, j.Search)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return true, fmt.Errorf("remove %s: %w", path, err)
	}
	return true, nil
}
