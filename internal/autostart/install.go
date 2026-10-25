package autostart

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const launchDaemonLabel = "io.github.steiale.lockplus.daemon"

// InstallAutostart sets up the LaunchAgent for the GUI app.
func InstallAutostart(appPath string) error {
	return installMacAutostart(appPath)
}

// RemoveAutostart removes the LaunchAgent.
func RemoveAutostart() error {
	return removeMacAutostart()
}

// --- macOS: LaunchAgent ---

func installMacAutostart(appPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(plistDir, 0755); err != nil {
		return fmt.Errorf("creating LaunchAgents dir: %w", err)
	}

	// XML-escape appPath to prevent plist injection from special characters.
	var b strings.Builder
	xml.EscapeText(&b, []byte(appPath))
	safeAppPath := b.String()

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.github.steiale.lockplus.gui</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
`, safeAppPath)

	return os.WriteFile(filepath.Join(plistDir, "io.github.steiale.lockplus.gui.plist"), []byte(plist), 0644)
}

func removeMacAutostart() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	// Tolerate "never installed".
	if err := os.Remove(filepath.Join(home, "Library", "LaunchAgents", "io.github.steiale.lockplus.gui.plist")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
