package update

import (
	"fmt"
	"os/exec"
	"runtime"
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
	switch runtime.GOOS {
	case "darwin":
		return installDarwin(filePath)
	case "linux":
		return installLinux(filePath)
	case "windows":
		return installWindows(filePath)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
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
		return exec.Command("open", "https://github.com/steiale/wireguide/releases/latest").Run()
	}
	return exec.Command("open", "-R", path).Run()
}

func installLinux(path string) error {
	// Try dpkg for .deb — use pkexec instead of sudo (works with GUI, no TTY needed)
	if len(path) > 4 && path[len(path)-4:] == ".deb" {
		return exec.Command("pkexec", "dpkg", "-i", path).Run()
	}
	// Try rpm for .rpm — use pkexec for the same reason
	if len(path) > 4 && path[len(path)-4:] == ".rpm" {
		return exec.Command("pkexec", "rpm", "-U", path).Run()
	}
	// AppImage — make executable and run
	if err := exec.Command("chmod", "+x", path).Run(); err != nil {
		return fmt.Errorf("chmod +x: %w", err)
	}
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		return err
	}
	// Release the process so it doesn't become a zombie when the parent exits.
	return cmd.Process.Release()
}

func installWindows(path string) error {
	// Run .msi installer
	if len(path) > 4 && path[len(path)-4:] == ".msi" {
		return exec.Command("msiexec", "/i", path).Run()
	}
	// Run .exe installer
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
