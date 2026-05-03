//go:build darwin

package elevate

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// xmlEscape returns s with XML-special characters escaped. Used when
// interpolating paths or labels into the LaunchDaemon plist so that an
// unexpected character (e.g. an ampersand in a future user-controlled path)
// cannot break the plist or inject elements.
func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

const (
	daemonLabel  = "io.github.steiale.wireguide-plus.helper"
	daemonPlist  = "/Library/LaunchDaemons/" + daemonLabel + ".plist"
	daemonBinary = "/Library/PrivilegedHelperTools/" + daemonLabel
)

// SpawnHelper starts the privileged helper process.
//
// On first launch: installs the LaunchDaemon (one-time admin password prompt
// via macOS native dialog). After that, the helper starts at boot via launchd
// and the app never asks for a password again.
//
// Flow:
//  1. Socket already live → helper running, return immediately.
//  2. Daemon not installed → install binary + plist + bootstrap (one-time sudo).
//  3. Daemon installed but not running → bootout + bootstrap to restart.
//  4. Dev fallback: if all else fails, osascript spawns helper directly.
func SpawnHelper(args Args) error {
	// 1. Already running? (skip check if force-reinstalling after version mismatch)
	if !args.ForceReinstall && isSocketLive(args.SocketPath) {
		slog.Info("helper already running")
		return nil
	}

	// 2-3. Install/restart daemon via a single osascript admin prompt.
	if err := installAndLoadDaemon(args); err != nil {
		return fmt.Errorf("daemon install failed: %w", err)
	}
	return nil
}

// installAndLoadDaemon writes the plist to a temp file (no escaping issues),
// then runs a shell script as root via osascript that copies everything into
// place and bootstraps the daemon. The user sees one password prompt.
func installAndLoadDaemon(args Args) error {
	exe, err := helperBinaryPath()
	if err != nil {
		return err
	}

	// Write plist to a temp file — avoids heredoc/escaping issues inside
	// the AppleScript string. Go writes it as the current user to /tmp,
	// then the root shell script copies it to /Library/LaunchDaemons/.
	uid := os.Getuid()
	// L2: XML-escape every interpolated value before embedding it in the
	// plist. The current values come from constants and our own argv so
	// this is defence-in-depth — but the moment a user-controlled path
	// (e.g. a custom data dir) flows in here, an unescaped `&` or `<`
	// would break the plist or open an injection vector.
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--helper</string>
        <string>--socket=%s</string>
        <string>--uid=%d</string>
        <string>--data-dir=%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/wireguide-plus-helper.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/wireguide-plus-helper.log</string>
</dict>
</plist>
`, xmlEscape(daemonLabel), xmlEscape(daemonBinary), xmlEscape(args.SocketPath), uid, xmlEscape(args.DataDir))

	tmpPlist := filepath.Join(os.TempDir(), daemonLabel+".plist")
	if err := os.WriteFile(tmpPlist, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write temp plist: %w", err)
	}
	defer os.Remove(tmpPlist)

	// Validate plist syntax before attempting install.
	if out, err := exec.Command("plutil", "-lint", tmpPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("plist validation failed: %s", strings.TrimSpace(string(out)))
	}

	// Single shell script that does everything as root:
	// 1. Create target directory
	// 2. Copy binary
	// 3. Copy plist (from our validated temp file)
	// 4. Set ownership/permissions
	// 5. (Re)load the daemon.
	//
	// L2: The previous flow ran `bootout` then `bootstrap`, leaving a brief
	// window with no helper running — long enough for an in-flight RPC to
	// see the socket disappear. Use `launchctl kickstart -k` instead: when
	// the service is already loaded it restarts it in-place with no gap.
	// If the service isn't loaded yet (first install or a previous
	// uninstall), `kickstart` fails with non-zero exit and we fall back to
	// `bootstrap` to load it from the plist.
	shellScript := fmt.Sprintf(
		`mkdir -p /Library/PrivilegedHelperTools && `+
			`cp -f %s %s && `+
			`xattr -d com.apple.quarantine %s 2>/dev/null; `+
			`chown root:wheel %s && `+
			`chmod 755 %s && `+
			`cp -f %s %s && `+
			`chown root:wheel %s && `+
			`chmod 644 %s && `+
			`(launchctl kickstart -k system/%s 2>/dev/null || launchctl bootstrap system %s)`,
		shellQuote(exe), shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(tmpPlist), shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		daemonLabel,
		shellQuote(daemonPlist),
	)

	escaped := strings.ReplaceAll(shellScript, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	osascriptCmd := fmt.Sprintf(
		`do shell script "%s" with administrator privileges with prompt "WireGuide+ needs administrator access to install its VPN helper service.\n\nThe helper runs as a background service to manage VPN tunnels, firewall rules, and network configuration. This prompt appears on first launch or after an app update."`,
		escaped,
	)

	slog.Info("installing LaunchDaemon (one-time admin prompt)")
	if err := exec.Command("osascript", "-e", osascriptCmd).Run(); err != nil {
		return fmt.Errorf("osascript install: %w", err)
	}

	// Do NOT poll for the socket here. After kickstart, launchd may apply a
	// throttle (default 10 s "ThrottleInterval") if the previous daemon
	// instance had been alive for less than 10 s — exactly what happens during
	// a version-upgrade flow where the GUI had just sent Shutdown to the old
	// helper. A short wait loop here would expire before launchd respawns,
	// causing SpawnHelper to return a spurious error and the GUI to show the
	// "grant administrator access" retry dialog even though the install
	// actually succeeded.
	//
	// The caller (ensureHelper in internal/gui) already polls the socket for
	// up to 60 s after SpawnHelper returns, which comfortably covers any
	// launchd throttle window.
	slog.Info("LaunchDaemon install/restart command issued; caller will poll for socket")
	return nil
}

// helperBinaryPath returns the path of the standalone helper binary.
//
// The helper binary (cmd/helper, no Wails/AppKit dependency) lives next to
// the GUI binary inside the .app bundle at:
//
//	WireGuide+.app/Contents/MacOS/wireguide-plus-helper
//
// Keeping it separate from the GUI binary prevents AppKit/WebKit framework
// +load methods from crashing when the daemon is launched as root without a
// window server.
func helperBinaryPath() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	dir := filepath.Dir(self)
	candidate := filepath.Join(dir, "wireguide-plus-helper")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}
	// Inside a .app bundle the helper MUST be present — falling back to the
	// GUI binary would silently reinstall the crashing Wails binary as the
	// root daemon, recreating the crash-loop we fixed in v1.0.22.
	if strings.HasSuffix(dir, ".app/Contents/MacOS") {
		return "", fmt.Errorf("helper binary missing from app bundle at %s (reinstall the app)", candidate)
	}
	slog.Warn("helper binary not found; falling back to self (dev build only)", "path", candidate)
	return self, nil
}

// isSocketLive checks whether the helper socket accepts a connection.
func isSocketLive(socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// shellQuote wraps a value in single quotes, escaping embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
