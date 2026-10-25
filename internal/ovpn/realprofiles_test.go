package ovpn

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestRealProfiles validates the developer's own saved profiles. Opt-in
// (LOCKPLUS_REAL_PROFILES=1) since it reads ~/Library. Logs directive NAMES
// only — never arguments or inline content, which carry secrets.
func TestRealProfiles(t *testing.T) {
	if os.Getenv("LOCKPLUS_REAL_PROFILES") == "" {
		t.Skip("set LOCKPLUS_REAL_PROFILES=1 to validate saved profiles")
	}
	home, _ := os.UserHomeDir()
	files, _ := filepath.Glob(filepath.Join(home, "Library/Application Support/lockplus/tunnels/*.ovpn"))
	if len(files) == 0 {
		t.Skip("no saved .ovpn profiles")
	}
	for i, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("profile #%d: %v", i+1, err)
		}
		ds, perr := parseConfig(data)
		seen := map[string]bool{}
		walkDirectives(ds, func(d *directive) bool {
			n := d.Name
			if d.Inline {
				n = "<" + n + ">"
			}
			if d.Name == "setenv" && len(d.Args) > 1 && d.Args[0] == "opt" {
				n = "setenv opt " + d.Args[1]
			}
			seen[n] = true
			return true
		})
		names := make([]string, 0, len(seen))
		for n := range seen {
			names = append(names, n)
		}
		sort.Strings(names)
		verr := ValidateOVPN(data)
		t.Logf("profile #%d: parseErr=%v validate=%v directives=[%s]", i+1, perr != nil, verr, strings.Join(names, " "))
		if verr != nil {
			t.Errorf("profile #%d rejected", i+1)
		}
	}
}
