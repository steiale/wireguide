//go:build darwin

package ovpn

/*
#cgo LDFLAGS: -framework Security -framework Foundation
#include <stdlib.h>

int keychainStoreGenericPassword(const char *service, const char *account, const unsigned char *secret, int secretLen);
int keychainLoadGenericPassword(const char *service, const char *account, unsigned char **outData, int *outLen);
int keychainDeleteGenericPassword(const char *service, const char *account);
*/
import "C"

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

// keychainService is the generic-password service name under which all OpenVPN
// credentials are stored. Each tunnel is a separate account within this service.
const keychainService = "io.github.steiale.lockplus.ovpn"

// errSecItemNotFound is Security.framework's stable, public OSStatus
// constant for "no such Keychain item" (Security/SecBase.h).
const errSecItemNotFound = -25300

// ErrCredentialsNotFound distinguishes "nothing stored for this tunnel"
// (expected, not an error worth surfacing) from a genuine Keychain failure
// (permission denied, locked/corrupted keychain) — callers previously
// couldn't tell these apart and treated every failure as "no saved creds",
// masking real problems as an empty-fields state.
var ErrCredentialsNotFound = errors.New("no credentials stored for this tunnel")

// Credentials holds an OpenVPN username and the *base* password (the static
// part the user typed once). For TOTP servers the actual password sent to the
// server is basePassword + the current 6-digit code; that combination happens
// at connect time and is never persisted.
type Credentials struct {
	Username     string
	BasePassword string
}

// StoreCredentials saves credentials to the Keychain via the native
// Security framework (SecItemAdd/SecItemUpdate) rather than shelling out to
// the `security` CLI. The secret never appears as a subprocess argument —
// the previous `security add-generic-password -w <secret>` briefly exposed
// it to any local process inspecting `ps`/`/proc` for the life of that
// subprocess. (The item is also created with
// kSecAttrAccessibleWhenUnlockedThisDeviceOnly, but see keychain_darwin.m's
// doc comment on keychainStoreGenericPassword: that attribute is only
// actually enforced on the data-protection keychain, which this code
// deliberately doesn't opt into — doing so would orphan existing users'
// already-saved credentials in the legacy keychain. Treat it as a declared
// intent, not a delivered guarantee, on this code path today.)
//
// Still uses the "b64:" + base64(...) wire format from the CLI era (not
// because the native API needs it — SecItemAdd stores arbitrary bytes fine
// — but to keep the on-disk format byte-identical to what
// LoadCredentials/decodeSecret already parses, so this is purely a
// transport change, not a format migration).
func StoreCredentials(tunnelName, username, basePassword string) error {
	secret := "b64:" + base64.StdEncoding.EncodeToString([]byte(username+"\n"+basePassword))
	secretBytes := []byte(secret)

	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(tunnelName)
	defer C.free(unsafe.Pointer(cAccount))

	status := C.keychainStoreGenericPassword(
		cService, cAccount,
		(*C.uchar)(unsafe.Pointer(&secretBytes[0])), C.int(len(secretBytes)),
	)
	if status != 0 {
		return fmt.Errorf("storing ovpn credentials for %q: Keychain OSStatus %d", tunnelName, int(status))
	}
	return nil
}

// LoadCredentials reads the stored secret for tunnelName and returns the parsed
// credentials. It handles multiple on-disk formats for forward/backward
// compatibility with items written by the previous `security`-CLI-based
// implementation:
//
//  1. Current ("b64:" prefix): base64-encoded "username\npassword".
//  2. Legacy hex: `security -w` used to hex-encode values containing
//     non-printable bytes. Old items written with a raw "\n" separator come
//     back as a hex string; hex-decode → split on "\n" gives the correct
//     result. The native API returns raw bytes with no such mangling, but
//     an item created back when the CLI wrote this format still reads back
//     exactly as it was stored.
//  3. Plain-text fallback (shouldn't exist in practice).
func LoadCredentials(tunnelName string) (*Credentials, error) {
	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(tunnelName)
	defer C.free(unsafe.Pointer(cAccount))

	var outData *C.uchar
	var outLen C.int
	status := C.keychainLoadGenericPassword(cService, cAccount, &outData, &outLen)
	if status != 0 {
		if int(status) == errSecItemNotFound {
			return nil, ErrCredentialsNotFound
		}
		return nil, fmt.Errorf("loading ovpn credentials for %q: Keychain OSStatus %d", tunnelName, int(status))
	}
	defer C.free(unsafe.Pointer(outData))
	raw := string(C.GoBytes(unsafe.Pointer(outData), outLen))

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
// LoadCredentials:
//
//   - "b64:..." prefix → base64-decode the suffix (current format).
//   - All-lowercase hex string → hex-decode (legacy: the `security` CLI
//     hex-encoded the raw "\n"-containing secret stored by versions before
//     v1.0.50).
//   - Anything else → return as-is.
func decodeSecret(raw string) (string, error) {
	if strings.HasPrefix(raw, "b64:") {
		b, err := base64.StdEncoding.DecodeString(raw[4:])
		if err != nil {
			return "", fmt.Errorf("base64 decode: %w", err)
		}
		return string(b), nil
	}
	// Legacy hex: the hex alphabet [0-9a-f] does not overlap with the
	// "b64:" prefix, so we can try it safely.
	if b, err := hex.DecodeString(raw); err == nil && len(b) > 0 {
		return string(b), nil
	}
	return raw, nil
}

// DeleteCredentials removes the stored secret for tunnelName. It is a no-op (no
// error) if no item exists, so callers can delete unconditionally on tunnel
// removal.
func DeleteCredentials(tunnelName string) error {
	cService := C.CString(keychainService)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(tunnelName)
	defer C.free(unsafe.Pointer(cAccount))

	status := C.keychainDeleteGenericPassword(cService, cAccount)
	if status != 0 {
		return fmt.Errorf("deleting ovpn credentials for %q: Keychain OSStatus %d", tunnelName, int(status))
	}
	return nil
}
