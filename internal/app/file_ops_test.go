package app

import (
	"strings"
	"testing"

	"github.com/steiale/wireguide/internal/storage"
)

func TestSanitizeTunnelName(t *testing.T) {
	cases := map[string]string{
		"office":                              "office",
		"Screenshot 2026-07-17 at 10.30.45":   "Screenshot 2026-07-17 at 10-30-45",
		"user@vpn.example.com":                "user-vpn-example-com",
		"..--weird__name--..":                 "weird__name",
		"   ":                                 "tunnel",
		"日本語":                                 "tunnel",
		strings.Repeat("a", 80):               strings.Repeat("a", 56),
		strings.Repeat("a", 55) + " b" + "cd": strings.Repeat("a", 55),
	}
	for in, want := range cases {
		got := sanitizeTunnelName(in)
		if got != want {
			t.Errorf("sanitizeTunnelName(%q) = %q, want %q", in, got, want)
		}
		if err := storage.ValidateTunnelName(got); err != nil {
			t.Errorf("sanitizeTunnelName(%q) = %q fails validation: %v", in, got, err)
		}
	}
}
