package update

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Install runs the OS-specific installer for the downloaded update.
// The caller must pass the UpdateInfo whose HashVerified field was set by
// DownloadUpdate. Install refuses to proceed if the hash was not verified.
//
// NOTE: On macOS, Install is currently never called from RunUpdate — Homebrew
// installs go through `brew upgrade` and non-Homebrew installs open the GitHub
// Releases page so the user can download/replace the app manually. The Install
// path is kept here for Linux/Windows where the OS package manager can
// actually consume the downloaded file. If a future macOS auto-update flow
// wants to swap the app bundle in place, it MUST call DownloadUpdate first
// (which runs SHA-256 verification) and then Install (which refuses to run
// without HashVerified=true). Do not bypass the verifier.
func Install(filePath string, info *UpdateInfo) error {
	if info == nil || !info.HashVerified {
		return fmt.Errorf("refusing to install: checksum was not verified")
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
		return exec.Command("open", "https://github.com/korjwl1/wireguide/releases/latest").Run()
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
