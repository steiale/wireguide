package update

import (
	"fmt"
	"os/exec"
)

// Install runs the OS-specific installer for the downloaded update. The
// caller must pass the UpdateInfo populated by DownloadUpdate, which sets
// HashVerified and/or SignatureVerified depending on what was available and
// what requireSignature demands (see checker.go). Install refuses to proceed
// unless AT LEAST ONE of the two actually verified — checking only
// HashVerified was wrong: no release in this project's history has ever
// published a separate checksum file (see checker.go's DownloadUpdate
// comment), so HashVerified is false for every real release today, and the
// non-brew macOS path below WAS called from settings_ops.go's RunUpdate
// (the comment previously claiming otherwise was stale) — meaning every
// real update silently failed at this exact check. The Ed25519 signature
// (SignatureVerified) is the actual cryptographic authenticity guarantee
// here — it's what requireSignature enforces DownloadUpdate can't skip —
// so it alone is sufficient; the checksum is optional defense-in-depth.
func Install(filePath string, info *UpdateInfo) error {
	if info == nil || !(info.HashVerified || info.SignatureVerified) {
		return fmt.Errorf("refusing to install: neither checksum nor signature was verified")
	}
	return installDarwin(filePath)
}

func installDarwin(path string) error {
	// Reveal the verified zip in Finder so the user can drag-replace the
	// app bundle manually. Auto-swapping a running .app on macOS needs
	// elevated privileges and has many failure modes; the indie-app
	// convention is to surface the download and let the user finish.
	// `path` is the SHA-256-verified file produced by DownloadUpdate.
	if path == "" {
		// Defensive: fall back to opening the releases page rather than
		// silently succeeding with nothing to install.
		return exec.Command("/usr/bin/open", "https://github.com/steiale/wireguide/releases/latest").Run()
	}
	return exec.Command("/usr/bin/open", "-R", path).Run()
}
