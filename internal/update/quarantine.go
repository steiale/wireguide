package update

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// quarantineXattr is the extended attribute Gatekeeper consults.
const quarantineXattr = "com.apple.quarantine"

// quarantineValue builds the standard "flags;hex-timestamp;agent;" value.
// 0083 = kLSQuarantineTypeOtherDownload-style flags as set by browsers, which
// makes LaunchServices/Gatekeeper assess the app on first open.
func quarantineValue(t time.Time) string {
	return fmt.Sprintf("0083;%x;LockPlus;", t.Unix())
}

// setQuarantine tags path with com.apple.quarantine. Go's HTTP client does
// not do this itself, so without it an auto-updated build would never be
// assessed by Gatekeeper.
func setQuarantine(path string, t time.Time) error {
	return unix.Setxattr(path, quarantineXattr, []byte(quarantineValue(t)), 0)
}
