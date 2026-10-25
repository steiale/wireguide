package wifi

import "testing"

const hardwarePorts = `
Hardware Port: Ethernet
Device: en0
Ethernet Address: 00:00:00:00:00:01

Hardware Port: Wi-Fi
Device: en1
Ethernet Address: 00:00:00:00:00:02

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: N/A

VLAN Configurations
===================
`

func TestWifiInterface(t *testing.T) {
	cases := map[string]string{
		hardwarePorts:                            "en1",
		"Hardware Port: Wi-Fi\nDevice: en0\n":    "en0",
		"Hardware Port: Ethernet\nDevice: en0\n": "",
		"":                                       "",
		"** Error: something went wrong\n":       "",
	}
	for in, want := range cases {
		if got := wifiInterface(in); got != want {
			t.Errorf("wifiInterface(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSummarySSID(t *testing.T) {
	summary := func(ssidLine string) string {
		return `<dictionary> {
  BSSID : 00:11:22:33:44:55
  IPv4 : <array> {
    0 : <dictionary> {
      ConfigMethod : DHCP
    }
  }
  InterfaceType : WiFi
  LinkStatusActive : TRUE
` + ssidLine + `  Security : WPA2_PSK
}
`
	}
	cases := map[string]string{
		summary("  SSID : Home Net\n"):                      "Home Net",
		summary("  SSID : a : b\n"):                         "a : b",
		summary("  SSID : <redacted>\n"):                    "",
		summary(""):                                         "", // not associated
		"<dictionary> {\n  InterfaceType : Ethernet\n}\n":   "",
		"ipconfig: getsummary en9 failed\n":                 "",
		"You are not associated with an AirPort network.\n": "",
		"": "",
	}
	for in, want := range cases {
		if got := parseSummarySSID(in); got != want {
			t.Errorf("parseSummarySSID(%q) = %q, want %q", in, got, want)
		}
	}
}
