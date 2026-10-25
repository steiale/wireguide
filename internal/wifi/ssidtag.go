package wifi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// ssidTagKeyFile holds the per-install HMAC key for SSIDTag, in the user's
// config dir.
const ssidTagKeyFile = "ssid-tag.key"

const ssidTagKeyLen = 32

var (
	ssidKeyMu sync.Mutex
	ssidKey   []byte
)

// SSIDTag returns a short pseudonym of ssid for Info-level logs: the first
// 6 bytes of HMAC-SHA256 under a random per-install key (InitSSIDTagKey).
// It keeps network names out of log files and shared diagnostics, and a
// tag can't be checked against a guessed SSID without the key file; it is
// a pseudonym, not encryption, and equal SSIDs get equal tags on this
// install. Empty stays empty (no Wi-Fi).
func SSIDTag(ssid string) string {
	if ssid == "" {
		return ""
	}
	mac := hmac.New(sha256.New, ssidTagKey())
	mac.Write([]byte(ssid))
	return "ssid#" + hex.EncodeToString(mac.Sum(nil)[:6])
}

// ssidTagKey returns the loaded key, or a random per-process key when
// InitSSIDTagKey was not called or failed (tags then differ per launch,
// but are never an unkeyed hash).
func ssidTagKey() []byte {
	ssidKeyMu.Lock()
	defer ssidKeyMu.Unlock()
	if ssidKey == nil {
		k := make([]byte, ssidTagKeyLen)
		if _, err := rand.Read(k); err != nil {
			panic(fmt.Sprintf("crypto/rand: %v", err))
		}
		ssidKey = k
	}
	return ssidKey
}

// InitSSIDTagKey loads the SSIDTag key from configDir, creating it once
// (random, mode 0600) if missing. A key file of the wrong size (e.g.
// truncated by a crash mid-write) that passes the ownership and permission
// checks is replaced; anything else suspicious is refused, never rewritten.
func InitSSIDTagKey(configDir string) error {
	k, err := loadOrCreateKey(filepath.Join(configDir, ssidTagKeyFile))
	if err != nil {
		return err
	}
	ssidKeyMu.Lock()
	ssidKey = k
	ssidKeyMu.Unlock()
	return nil
}

// errKeySize marks a key file that is ours (regular, owned by us, 0600) but
// has the wrong length: safe to replace.
var errKeySize = errors.New("unexpected key length")

func loadOrCreateKey(path string) ([]byte, error) {
	k, err := readKey(path)
	switch {
	case err == nil:
		return k, nil
	case errors.Is(err, errKeySize):
		return replaceKey(path)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	k, err = newKey()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return readKey(path) // created concurrently
	}
	if err != nil {
		return nil, err
	}
	_, werr := f.Write(k)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return nil, werr
	}
	return k, nil
}

func newKey() ([]byte, error) {
	k := make([]byte, ssidTagKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// replaceKey atomically replaces an invalid key file with a fresh key: a
// new 0600 file created exclusively (O_EXCL, O_NOFOLLOW: never an existing
// file or symlink) next to it, synced, then renamed over it. Returns the
// key the file holds afterwards (a concurrent launch may have won).
func replaceKey(path string) ([]byte, error) {
	k, err := newKey()
	if err != nil {
		return nil, err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return nil, err
	}
	tmp := path + ".tmp-" + hex.EncodeToString(suffix)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	_, werr := f.Write(k)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return nil, werr
	}
	if got, err := readKey(path); err == nil {
		return got, nil
	}
	return k, nil
}

// readKey reads the key file, refusing symlinks (O_NOFOLLOW), non-regular
// files, files owned by someone else, loose permissions and wrong sizes
// (errKeySize). The checks run on the opened descriptor (Fstat), so the file
// checked is the file read.
func readKey(path string) ([]byte, error) {
	// O_NONBLOCK: opening a FIFO planted there must not hang; the
	// regular-file check below rejects it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symlink", path)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("%s is owned by uid %d", path, st.Uid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has insecure mode %v", path, fi.Mode().Perm())
	}
	k, err := io.ReadAll(io.LimitReader(f, ssidTagKeyLen+1))
	if err != nil {
		return nil, err
	}
	if len(k) != ssidTagKeyLen {
		return nil, fmt.Errorf("%s: %w %d", path, errKeySize, len(k))
	}
	return k, nil
}
