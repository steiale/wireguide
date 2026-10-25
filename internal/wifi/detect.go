// Package wifi provides Wi-Fi SSID detection and auto-connect rules.
package wifi

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// CurrentSSID returns the current Wi-Fi SSID, or "" if not associated or
// unknown. The airport tool is gone and `networksetup -getairportnetwork`
// reports "not associated" on current macOS, so this reads
// `ipconfig getsummary <wifi-if>`. macOS returns "<redacted>" there for
// processes without Location Services access; that is treated as unknown.
func CurrentSSID() string {
	iface := wifiInterface(run("/usr/sbin/networksetup", "-listallhardwareports"))
	if iface == "" {
		return ""
	}
	return parseSummarySSID(run("/usr/sbin/ipconfig", "getsummary", iface))
}

func run(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// wifiInterface finds the device of the "Wi-Fi" hardware port in
// `networksetup -listallhardwareports` output ("" if none).
func wifiInterface(out string) string {
	inWiFi := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if port, ok := strings.CutPrefix(line, "Hardware Port:"); ok {
			port = strings.TrimSpace(port)
			inWiFi = port == "Wi-Fi" || port == "AirPort"
			continue
		}
		if dev, ok := strings.CutPrefix(line, "Device:"); ok && inWiFi {
			return strings.TrimSpace(dev)
		}
	}
	return ""
}

// parseSummarySSID extracts the "SSID : <name>" line of
// `ipconfig getsummary` output. Anything else (errors, not associated,
// redacted) yields "".
func parseSummarySSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), " : ")
		if !ok || key != "SSID" {
			continue
		}
		if val == "<redacted>" {
			return ""
		}
		return val
	}
	return ""
}
