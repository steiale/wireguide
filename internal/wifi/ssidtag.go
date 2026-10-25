package wifi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
// (random, mode 0600, never overwritten) if missing.
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

func loadOrCreateKey(path string) ([]byte, error) {
	if k, err := readKey(path); err == nil {
		return k, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	k := make([]byte, ssidTagKeyLen)
	if _, err := rand.Read(k); err != nil {
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

// readKey reads the key file, refusing symlinks, non-regular files, loose
// permissions and wrong sizes.
func readKey(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has insecure mode %v", path, fi.Mode().Perm())
	}
	k, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(k) != ssidTagKeyLen {
		return nil, fmt.Errorf("%s: unexpected key length %d", path, len(k))
	}
	return k, nil
}
