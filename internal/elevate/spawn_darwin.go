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
	// helperLogPath receives the helper's stdout/stderr (including openvpn's
	// stderr, which can echo config/credential details), so the install
	// script pre-creates it root:wheel 0600 before launchd opens it.
	helperLogPath = "/var/log/lockplus-helper.log"

	// teamRequirement pins every binary the root install script copies out
	// of the (user-writable) app bundle to our Developer ID team; each check
	// also pins the binary's signing identifier (see codeSignRequirement).
	// Dev (build/darwin/Taskfile.yml) and release (wails3 tool sign) builds
	// both sign with this team and both yield the file-name identifiers below.
	teamRequirement = `anchor apple generic and certificate leaf[subject.OU] = "M53GHX9FAY"`

	helperIdentifier  = "lockplus-helper"
	openvpnIdentifier = "openvpn"
)

// codeSignRequirement is the requirement for a binary signed with identifier,
// so one of our signed binaries can't be installed in place of another.
func codeSignRequirement(identifier string) string {
	return teamRequirement + ` and identifier "` + identifier + `"`
}

// verifySignatureSnippet returns a shell fragment (for the root install
// script) that verifies path against codeSignRequirement(identifier) and, on
// failure, deletes path and aborts the script with a SIGNATURE_INVALID marker
// that installAndLoadDaemon turns into a *SignatureError.
func verifySignatureSnippet(path, identifier string) string {
	return fmt.Sprintf(
		`CSERR=$(/usr/bin/codesign --verify --strict -R=%s %s 2>&1) || { /bin/rm -f %s; echo "SIGNATURE_INVALID: %s: $CSERR"; exit 5; }; `,
		shellQuote(codeSignRequirement(identifier)), shellQuote(path), shellQuote(path), path,
	)
}

// installBinarySnippet copies src from the app bundle to dst as root. The
// copy is made root-only (umask 077) under a temporary name in dst's
// directory, verified, and only then made executable and renamed into
// place, so nothing is ever world-readable before verification (a swapped-in
// symlink can't expose root-readable content). The rename also gives dst a
// fresh inode: overwriting an executed binary in place can wedge
// syspolicyd's per-file approval cache into a codesigning kill loop.
func installBinarySnippet(src, dst, identifier string) string {
	tmp := dst + ".new"
	q, qs, qt := shellQuote(dst), shellQuote(src), shellQuote(tmp)
	return fmt.Sprintf(
		`if [ -L %s ]; then echo "SIGNATURE_INVALID: %s is a symlink"; exit 5; fi; `+
			`rm -f %s; (umask 077 && cp %s %s); chown root:wheel %s; `+
			`xattr -d com.apple.quarantine %s 2>/dev/null || true; `+
			`%s`+
			`chmod 755 %s; mv -f %s %s; `,
		qs, src,
		qt, qs, qt, qt,
		qt,
		verifySignatureSnippet(tmp, identifier),
		qt, qt, q,
	)
}

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

// installAndLoadDaemon runs a shell script as root via osascript that copies
// the binaries and the (embedded) plist into place and bootstraps the
// daemon. The user sees one password prompt.
func installAndLoadDaemon(args Args) error {
	exe, err := helperBinaryPath()
	if err != nil {
		return err
	}

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
    <string>%s</string>
    <key>StandardOutPath</key>
    <string>%s</string>
</dict>
</plist>
`, xmlEscape(daemonLabel), xmlEscape(daemonBinary), xmlEscape(args.SocketPath), uid, xmlEscape(args.DataDir),
		xmlEscape(helperLogPath), xmlEscape(helperLogPath))

	// Lint the plist via a throwaway temp file that the root script never
	// reads: the real plist is base64-embedded in the script, so root never
	// trusts a path a same-user process could swap.
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
	shellScript := buildInstallScript(exe, plistB64)

	escaped := strings.ReplaceAll(shellScript, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	osascriptCmd := fmt.Sprintf(
		`do shell script "%s" with administrator privileges with prompt "LockPlus needs administrator access to install its VPN helper service.\n\nThe helper runs as a background service to manage VPN tunnels, firewall rules, and network configuration. This prompt appears on first launch or after an app update."`,
		escaped,
	)

	slog.Info("installing LaunchDaemon (one-time admin prompt)")
	// Capture combined output: osascript relays the shell script's stdout (our
	// INSTALL_OK / BOOTSTRAP_FAILED / SIGNATURE_INVALID markers) and any error
	// text on failure.
	out, err := exec.Command("/usr/bin/osascript", "-e", osascriptCmd).CombinedOutput()
	return interpretInstallOutput(strings.TrimSpace(string(out)), err)
}

// buildInstallScript returns the shell script run as root (via osascript)
// to install the helper. exe is the helper binary inside the app bundle;
// plistB64 is the base64-encoded LaunchDaemon plist.
func buildInstallScript(exe, plistB64 string) string {
	// The bundled openvpn (Contents/MacOS/openvpn) goes next to the helper,
	// which finds it via filepath.Dir(os.Args[0]). Optional: dev builds
	// without it still install the helper.
	ovpnExe := filepath.Join(filepath.Dir(exe), "openvpn")
	ovpnDst := "/Library/PrivilegedHelperTools/openvpn"
	ovpnSnippet := fmt.Sprintf(`if [ -e %s ] || [ -L %s ]; then %sfi; `,
		shellQuote(ovpnExe), shellQuote(ovpnExe), installBinarySnippet(ovpnExe, ovpnDst, openvpnIdentifier))

	// Runs as root via osascript. set -e aborts on any failure; markers on
	// stdout (INSTALL_OK, BOOTSTRAP_FAILED, SIGNATURE_INVALID) tell
	// interpretInstallOutput what happened. Bootstrap errors are surfaced,
	// not suppressed, so the GUI can show something actionable.
	return fmt.Sprintf(
		`set -e; `+
			// Pin PATH: bare commands must not resolve via the user's PATH.
			`export PATH="/usr/bin:/bin:/usr/sbin:/sbin"; `+
			`launchctl bootout system/`+daemonLabel+` 2>/dev/null || true; `+
			`launchctl bootout system/com.wireguide.helper 2>/dev/null || true; `+
			`rm -f /Library/LaunchDaemons/com.wireguide.helper.plist; `+
			`rm -f /Library/PrivilegedHelperTools/com.wireguide.helper; `+
			`mkdir -p /Library/PrivilegedHelperTools; `+
			`%s`+ // helper binary
			// The plist is decoded straight from the blob in this script.
			`printf '%%s' %s | base64 -d > %s; `+
			`chown root:wheel %s; `+
			`chmod 644 %s; `+
			`%s`+ // openvpn
			// The log receives openvpn's stderr: pre-create it root-only
			// before launchd opens it (and tighten an older 0644 one).
			`/usr/bin/touch %s; /usr/sbin/chown root:wheel %s; /bin/chmod 600 %s; `+
			// Clear a persistent disabled state (Login Items block or
			// `launchctl disable`): bootstrap would succeed but never start.
			`launchctl enable system/%s 2>/dev/null || true; `+
			// kickstart restarts a loaded service; otherwise bootstrap it.
			`if launchctl kickstart -k system/%s 2>/dev/null; then :; `+
			`else BOOTERR=$(launchctl bootstrap system %s 2>&1) || { echo "BOOTSTRAP_FAILED: $BOOTERR"; exit 3; }; fi; `+
			`if launchctl print system/%s >/dev/null 2>&1; then echo INSTALL_OK; `+
			`else echo "BOOTSTRAP_FAILED: service not registered after load"; exit 4; fi`,
		installBinarySnippet(exe, daemonBinary, helperIdentifier),
		shellQuote(plistB64), shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		ovpnSnippet,
		shellQuote(helperLogPath), shellQuote(helperLogPath), shellQuote(helperLogPath),
		daemonLabel,
		daemonLabel,
		shellQuote(daemonPlist),
		daemonLabel,
	)
}

// interpretInstallOutput maps the install script's osascript output and exit
// error to the typed errors callers (the GUI) react to.
func interpretInstallOutput(outStr string, err error) error {
	if err != nil {
		// Distinguish the two common failure modes so the GUI can react:
		//  - launchd refused to load the daemon (our explicit BOOTSTRAP_FAILED
		//    marker, echoed by the script before `exit 3`/`exit 4`)
		//  - user cancelled the password prompt (osascript error -128)
		if strings.Contains(outStr, "SIGNATURE_INVALID") {
			slog.Error("helper install aborted: code signature verification failed", "output", outStr)
			return &SignatureError{Output: outStr, Err: err}
		}
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

// SignatureError indicates the root install script refused to install a
// binary copied from the app bundle (helper or openvpn) because it failed
// `codesign --verify` against codeSignRequirement. The offending file was
// deleted. Retrying won't help until the app bundle is replaced with a
// correctly signed build.
type SignatureError struct {
	Output string
	Err    error
}

func (e *SignatureError) Error() string {
	return fmt.Sprintf("helper install aborted: code signature verification failed (reinstall LockPlus from an official release): %s", e.Output)
}

func (e *SignatureError) Unwrap() error { return e.Err }

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
	// No fallback to the GUI binary: it would fail the identifier pin anyway,
	// and as a root daemon it crashes (AppKit without a window server).
	if _, err := os.Stat(candidate); err != nil {
		return "", fmt.Errorf("helper binary missing at %s (reinstall the app): %w", candidate, err)
	}
	return candidate, nil
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
