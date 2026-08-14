//go:build darwin

package elevate

import (
	"bytes"
	"encoding/base64"
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
	daemonLabel  = "io.github.steiale.lockplus.helper"
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
    <string>/var/log/lockplus-helper.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/lockplus-helper.log</string>
</dict>
</plist>
`, xmlEscape(daemonLabel), xmlEscape(daemonBinary), xmlEscape(args.SocketPath), uid, xmlEscape(args.DataDir))

	// Validate plist syntax using a throwaway file at an unpredictable path
	// (os.CreateTemp, not a fixed name) purely for our own linting — it is
	// NEVER referenced by the privileged shell script below. Writing the
	// real plist to a fixed, predictable, user-owned path and then having
	// root's shell `cp` it moments later (the previous approach) was a
	// TOCTOU: any other process running as the same user could swap the
	// file's contents in that window and get root to install an
	// attacker-controlled LaunchDaemon. Instead we base64-embed the
	// in-memory plist string directly into the root-run shell script, so
	// root never trusts a path a co-located process could have raced.
	lintFile, err := os.CreateTemp("", daemonLabel+"-lint-*.plist")
	if err != nil {
		return fmt.Errorf("create lint temp file: %w", err)
	}
	lintPath := lintFile.Name()
	_, writeErr := lintFile.Write([]byte(plist))
	closeErr := lintFile.Close()
	defer os.Remove(lintPath)
	if writeErr != nil {
		return fmt.Errorf("write lint temp file: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close lint temp file: %w", closeErr)
	}
	if out, err := exec.Command("/usr/bin/plutil", "-lint", lintPath).CombinedOutput(); err != nil {
		return fmt.Errorf("plist validation failed: %s", strings.TrimSpace(string(out)))
	}
	plistB64 := base64.StdEncoding.EncodeToString([]byte(plist))

	// If the app bundle ships an openvpn binary (Contents/MacOS/openvpn), copy
	// it to /Library/PrivilegedHelperTools/openvpn so the helper can find it
	// via filepath.Dir(os.Args[0]). The copy is conditional — dev builds that
	// lack the binary still install the helper successfully.
	ovpnExe := filepath.Join(filepath.Dir(exe), "openvpn")
	ovpnDst := "/Library/PrivilegedHelperTools/openvpn"
	// rm the destination before cp: overwriting an already-executed binary's
	// file in place (same inode) has been observed to poison syspolicyd's
	// per-file exec-approval cache on some macOS versions, permanently
	// wedging that inode into an "OS_REASON_CODESIGNING" kill loop even
	// though the binary is validly signed and notarized (spctl/codesign both
	// pass). rm+cp gets a fresh inode and avoids the whole class of bug.
	ovpnSnippet := fmt.Sprintf(
		`if [ -f %s ]; then rm -f %s; cp -f %s %s && xattr -d com.apple.quarantine %s 2>/dev/null || true; chown root:wheel %s && chmod 755 %s; fi; `,
		shellQuote(ovpnExe), shellQuote(ovpnDst), shellQuote(ovpnExe), shellQuote(ovpnDst), shellQuote(ovpnDst),
		shellQuote(ovpnDst), shellQuote(ovpnDst),
	)

	// The shell script runs as root via osascript. It is structured so that a
	// failure at any step aborts (set -e) and prints a recognisable marker on
	// stdout. We DELIBERATELY do not suppress errors on the bootstrap step:
	// when launchd refuses to load the daemon (blocked Login Item, bad
	// signature, ...) we need that error text to surface back to Go so the GUI
	// can show something actionable instead of silently looping.
	//
	// Flow inside the script:
	//  1. bootout the current + legacy labels (ignore "not loaded" errors).
	//  2. Remove legacy binary/plist.
	//  3. Copy the fresh helper binary + plist into place, fix ownership.
	//  4. (conditionally) copy the bundled openvpn binary.
	//  5. Try `kickstart -k` (in-place restart of an already-loaded service);
	//     if that fails (service not loaded), `bootstrap` it from the plist.
	//     Bootstrap errors are NOT suppressed.
	//  6. Verify with `launchctl print` that the service is actually
	//     registered. If it is not, emit BOOTSTRAP_FAILED so Go can detect it.
	//
	// We echo a leading "INSTALL_OK" only when everything (including the
	// verification) succeeds. Its presence/absence is how Go distinguishes a
	// real success from a partial one.
	shellScript := fmt.Sprintf(
		`set -e; `+
			// Pin PATH to the standard system directories before running
			// anything else. Without this, every bare command below (cp, rm,
			// chown, launchctl, ...) resolves via the invoking user's PATH —
			// a same-user process could plant a malicious binary earlier in
			// PATH and have it silently execute as root inside this script.
			`export PATH="/usr/bin:/bin:/usr/sbin:/sbin"; `+
			`launchctl bootout system/`+daemonLabel+` 2>/dev/null || true; `+
			`launchctl bootout system/com.wireguide.helper 2>/dev/null || true; `+
			`rm -f /Library/LaunchDaemons/com.wireguide.helper.plist; `+
			`rm -f /Library/PrivilegedHelperTools/com.wireguide.helper; `+
			`mkdir -p /Library/PrivilegedHelperTools; `+
			// rm before cp — see ovpnSnippet comment above for why overwriting
			// the existing binary's inode in place is unsafe.
			`rm -f %s; `+
			`cp -f %s %s; `+
			`xattr -d com.apple.quarantine %s 2>/dev/null || true; `+
			`chown root:wheel %s; `+
			`chmod 755 %s; `+
			// Decode the plist directly to its destination from the
			// base64 blob embedded in this script — root never reads a
			// path a co-located user process could have raced (see the
			// lintFile comment above).
			`printf '%%s' %s | base64 -d > %s; `+
			`chown root:wheel %s; `+
			`chmod 644 %s; `+
			ovpnSnippet+
			// Ensure launchd's persistent disabled-state is cleared before we
			// try to load the daemon. Without this, a prior macOS Login Items
			// block (or an explicit `launchctl disable`) keeps the service
			// disabled even after the plist is in place — bootstrap then
			// succeeds (exit 0) but the daemon never actually starts.
			`launchctl enable system/%s 2>/dev/null || true; `+
			// Load the daemon. kickstart restarts an already-loaded service in
			// place; if it isn't loaded yet, bootstrap it. Capture bootstrap's
			// error so it ends up in the osascript output.
			`if launchctl kickstart -k system/%s 2>/dev/null; then :; `+
			`else BOOTERR=$(launchctl bootstrap system %s 2>&1) || { echo "BOOTSTRAP_FAILED: $BOOTERR"; exit 3; }; fi; `+
			// Verify the service is now registered. `launchctl print` exits
			// non-zero if the label is unknown to launchd.
			`if launchctl print system/%s >/dev/null 2>&1; then echo INSTALL_OK; `+
			`else echo "BOOTSTRAP_FAILED: service not registered after load"; exit 4; fi`,
		shellQuote(daemonBinary),
		shellQuote(exe), shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(plistB64), shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		daemonLabel,             // enable system/%s
		daemonLabel,             // kickstart -k system/%s
		shellQuote(daemonPlist), // bootstrap system %s
		daemonLabel,             // print system/%s
	)

	escaped := strings.ReplaceAll(shellScript, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	osascriptCmd := fmt.Sprintf(
		`do shell script "%s" with administrator privileges with prompt "LockPlus needs administrator access to install its VPN helper service.\n\nThe helper runs as a background service to manage VPN tunnels, firewall rules, and network configuration. This prompt appears on first launch or after an app update."`,
		escaped,
	)

	slog.Info("installing LaunchDaemon (one-time admin prompt)")
	// Capture combined output: osascript relays the shell script's stdout (our
	// INSTALL_OK / BOOTSTRAP_FAILED markers) and any error text on failure.
	out, err := exec.Command("osascript", "-e", osascriptCmd).CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	if err != nil {
		// Distinguish the two common failure modes so the GUI can react:
		//  - launchd refused to load the daemon (our explicit BOOTSTRAP_FAILED
		//    marker, echoed by the script before `exit 3`/`exit 4`)
		//  - user cancelled the password prompt (osascript error -128)
		if strings.Contains(outStr, "BOOTSTRAP_FAILED") {
			slog.Error("LaunchDaemon bootstrap failed", "output", outStr)
			return &BootstrapError{Output: outStr, Err: err}
		}
		if strings.Contains(outStr, "-128") || strings.Contains(strings.ToLower(outStr), "cancel") {
			return ErrUserCancelled
		}
		return fmt.Errorf("osascript install failed: %s (%w)", outStr, err)
	}

	// osascript returned 0 but double-check the success marker is present —
	// `do shell script` only fails on a non-zero exit, and our `set -e` +
	// explicit `exit` calls cover the error paths, but a belt-and-braces check
	// here guards against a future script edit that swallows an error.
	if !strings.Contains(outStr, "INSTALL_OK") {
		slog.Error("LaunchDaemon install produced no success marker", "output", outStr)
		return &BootstrapError{Output: outStr, Err: fmt.Errorf("install did not confirm success")}
	}

	slog.Info("LaunchDaemon installed and verified registered", "output", outStr)
	return nil
}

// ErrUserCancelled indicates the user dismissed the admin-password prompt
// rather than authorizing it. Like BootstrapError, this is terminal for the
// current attempt — retrying immediately just re-shows the same prompt — so
// callers (e.g. the GUI's health-monitor recovery loop) should treat it the
// same way: stop auto-retrying rather than counting it as one of a bounded
// number of transient-failure retries.
var ErrUserCancelled = fmt.Errorf("admin authorization cancelled by user")

// BootstrapError indicates the LaunchDaemon was copied into place but launchd
// refused to load it (most commonly because macOS has the background item in a
// blocked state under System Settings → General → Login Items & Extensions, or
// because the binary's signature is not trusted). The GUI inspects for this
// type to show a targeted recovery dialog instead of the generic retry loop.
type BootstrapError struct {
	Output string
	Err    error
}

func (e *BootstrapError) Error() string {
	return fmt.Sprintf("launchd refused to load the helper daemon: %s", e.Output)
}

func (e *BootstrapError) Unwrap() error { return e.Err }

// helperBinaryPath returns the path of the standalone helper binary.
//
// The helper binary (cmd/helper, no Wails/AppKit dependency) lives next to
// the GUI binary inside the .app bundle at:
//
//	LockPlus.app/Contents/MacOS/lockplus-helper
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
	candidate := filepath.Join(dir, "lockplus-helper")
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
