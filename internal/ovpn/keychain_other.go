//go:build !darwin

// Non-darwin fallback: shells out to the macOS `security` CLI, which
// doesn't exist on these platforms, so every call here will fail at
// runtime. Kept only so the ovpn package still compiles cross-platform
// (network/firewall/elevate all have real per-platform implementations;
// this one never had a functional non-macOS backend to begin with — OpenVPN
// credential storage on Linux/Windows would need its own native
// implementation, e.g. libsecret or DPAPI, which is out of scope here).
// See keychain_darwin.go for the real (native Security.framework) macOS
// implementation.
package ovpn

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// keychainService is the generic-password service name under which all OpenVPN
// credentials are stored. Each tunnel is a separate account within this service.
const keychainService = "io.github.steiale.lockplus.ovpn"

// ErrCredentialsNotFound distinguishes "nothing stored for this tunnel"
// (expected, not an error worth surfacing) from a genuine Keychain failure
// (permission denied, locked/corrupted keychain, `security` missing) —
// callers previously couldn't tell these apart and treated every failure as
// "no saved creds", masking real problems as an empty-fields state.
var ErrCredentialsNotFound = errors.New("no credentials stored for this tunnel")

// Credentials holds an OpenVPN username and the *base* password (the static
// part the user typed once). For TOTP servers the actual password sent to the
// server is basePassword + the current 6-digit code; that combination happens
// at connect time and is never persisted.
type Credentials struct {
	Username     string
	BasePassword string
}

// StoreCredentials saves credentials as a prefixed base64 string so that the
// stored value contains only printable ASCII. macOS `security find-generic-password -w`
// hex-encodes stored values that contain non-printable bytes (like the "\n"
// separator), which broke the earlier format. The new format is:
//
//	"b64:" + base64(username + "\n" + basePassword)
//
// KNOWN LIMITATION: the secret is passed as a `security` CLI argument, which
// is visible (briefly, for the life of this subprocess) to other processes
// on the same machine via `ps`/`/proc`. `security`'s own `--help` suggests
// passing `-w` as the last flag with no value to get an interactive
// getpass()-style prompt instead — verified empirically that this does NOT
// work here: getpass() reads directly from /dev/tty, bypassing stdin
// redirection entirely, and this code runs inside a root LaunchDaemon with
// no controlling terminal, so the prompt would block forever waiting for
// input that can never arrive. Properly avoiding argv exposure (and
// getting proper kSecAttrAccessibleWhenUnlockedThisDeviceOnly-style ACL
// hardening — also not exposed by the `security` CLI) requires calling the
// Security framework's SecItemAdd/SecItemCopyMatching directly via CGo
// instead of shelling out — a larger rewrite intentionally left for a
// dedicated follow-up rather than a rushed change here.
func StoreCredentials(tunnelName, username, basePassword string) error {
	secret := "b64:" + base64.StdEncoding.EncodeToString([]byte(username+"\n"+basePassword))
	cmd := exec.Command("security", "add-generic-password",
		"-a", tunnelName,
		"-s", keychainService,
		"-w", secret,
		"-U", // update if the item already exists
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("storing ovpn credentials for %q: %w (%s)", tunnelName, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// LoadCredentials reads the stored secret for tunnelName and returns the parsed
// credentials. It handles multiple on-disk formats for forward/backward
// compatibility:
//
//  1. Current ("b64:" prefix): base64-encoded "username\npassword".
//  2. Legacy hex: macOS `security -w` hex-encodes values containing non-printable
//     bytes. Old items written with a raw "\n" separator come back as a hex string;
//     hex-decode → split on "\n" gives the correct result.
//  3. Plain-text fallback (shouldn't exist in practice).
func LoadCredentials(tunnelName string) (*Credentials, error) {
	cmd := exec.Command("security", "find-generic-password",
		"-a", tunnelName,
		"-s", keychainService,
		"-w", // print only the password (the secret) to stdout
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(stderr.String(), "could not be found") {
			return nil, ErrCredentialsNotFound
		}
		return nil, fmt.Errorf("loading ovpn credentials for %q: %w (%s)", tunnelName, err, strings.TrimSpace(stderr.String()))
	}
	// `security -w` appends a trailing newline; strip exactly one.
	raw := strings.TrimSuffix(stdout.String(), "\n")

	payload, err := decodeSecret(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding stored credentials for %q: %w", tunnelName, err)
	}

	parts := strings.SplitN(payload, "\n", 2)
	creds := &Credentials{Username: parts[0]}
	if len(parts) == 2 {
		creds.BasePassword = parts[1]
	}
	return creds, nil
}

// decodeSecret resolves the on-disk encoding of the raw value returned by
// `security find-generic-password -w`:
//
//   - "b64:..." prefix → base64-decode the suffix (current format).
//   - All-lowercase hex string → hex-decode (legacy: security hex-encoded the
//     raw "\n"-containing secret stored by versions before v1.0.50).
//   - Anything else → return as-is.
func decodeSecret(raw string) (string, error) {
	if strings.HasPrefix(raw, "b64:") {
		b, err := base64.StdEncoding.DecodeString(raw[4:])
		if err != nil {
			return "", fmt.Errorf("base64 decode: %w", err)
		}
		return string(b), nil
	}
	// Legacy hex: `security` hex-encodes binary passwords. The hex alphabet
	// [0-9a-f] does not overlap with the "b64:" prefix, so we can try it safely.
	if b, err := hex.DecodeString(raw); err == nil && len(b) > 0 {
		return string(b), nil
	}
	return raw, nil
}

// DeleteCredentials removes the stored secret for tunnelName. It is a no-op (no
// error) if no item exists, so callers can delete unconditionally on tunnel
// removal.
func DeleteCredentials(tunnelName string) error {
	cmd := exec.Command("security", "delete-generic-password",
		"-a", tunnelName,
		"-s", keychainService,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// security exits non-zero when the item doesn't exist; treat that as success.
		if strings.Contains(stderr.String(), "could not be found") {
			return nil
		}
		return fmt.Errorf("deleting ovpn credentials for %q: %w (%s)", tunnelName, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
