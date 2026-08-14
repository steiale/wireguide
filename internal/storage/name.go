package storage

import (
	"fmt"
	"strings"
)

// windowsReservedNames are device names Windows treats specially regardless
// of extension (CON, CON.txt, con.conf are all the console device). Storage
// paths here are cross-platform (this package also builds for windows), so
// a tunnel literally named one of these would address a device file instead
// of a real one on that platform.
var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// ValidateTunnelName ensures a tunnel name is safe for use as a filesystem
// path (preventing traversal) and consistent across all entry points —
// both on first save and on rename. Allowed: letters, digits, '-', '_', spaces.
// Leading/trailing spaces are rejected to avoid confusing filenames.
// Length limit guards against filesystem limits on some platforms.
func ValidateTunnelName(name string) error {
	if name == "" {
		return fmt.Errorf("tunnel name is empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("tunnel name too long (max 64 characters)")
	}
	if name[0] == ' ' || name[len(name)-1] == ' ' {
		return fmt.Errorf("tunnel name cannot start or end with a space")
	}
	if windowsReservedNames[strings.ToUpper(name)] {
		return fmt.Errorf("%q is a reserved device name on Windows", name)
	}
	for _, r := range name {
		valid := (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == ' '
		if !valid {
			return fmt.Errorf("invalid character in tunnel name %q (letters, digits, '-', '_' and spaces only)", name)
		}
	}
	return nil
}
