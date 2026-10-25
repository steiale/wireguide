// Package wifi provides Wi-Fi SSID detection and auto-connect rules.
package wifi

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// coreWLANInfo is what the native CoreWLAN probe reports.
type coreWLANInfo struct {
	HasInterface bool   // a Wi-Fi interface exists
	Associated   bool   // interface is powered and in station mode
	Interface    string // BSD name, e.g. "en0" ("" if unknown)
	SSID         string // "" when not associated OR not Location-authorized
}

// ssidSource bundles the platform probes so the decision logic in resolve
// can be unit-tested with fakes.
type ssidSource struct {
	auth func() AuthStatus
	wlan func() coreWLANInfo
	run  func(name string, args ...string) string
}

var defaultSource = ssidSource{auth: nativeAuthStatus, wlan: nativeWiFiInfo, run: run}

// ssidBudget caps how long CurrentSSID may block its caller. A slow probe
// keeps running in the background; callers get the last known value.
const ssidBudget = 3 * time.Second

var (
	ssidMu       sync.Mutex
	ssidInflight chan struct{}
	ssidLast     string
)

// CurrentSSID returns the current Wi-Fi SSID, or "" if not associated or
// unknown (e.g. Location Services not authorized). It never blocks longer
// than ssidBudget, and concurrent callers share one in-flight probe.
func CurrentSSID() string {
	ssidMu.Lock()
	ch := ssidInflight
	if ch == nil {
		ch = make(chan struct{})
		ssidInflight = ch
		go func() {
			v := defaultSource.resolve()
			ssidMu.Lock()
			ssidLast = v
			ssidInflight = nil
			ssidMu.Unlock()
			close(ch)
		}()
	}
	ssidMu.Unlock()

	timer := time.NewTimer(ssidBudget)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
	}
	ssidMu.Lock()
	defer ssidMu.Unlock()
	return ssidLast
}

// resolve decides which source to trust:
//   - CoreWLAN SSID present            → use it (only possible when authorized)
//   - no Wi-Fi interface               → ""
//   - authorized but not associated    → "" (no subprocess needed)
//   - otherwise (unauthorized, or CoreWLAN returned nil while associated)
//     → ipconfig/networksetup fallback, which ignores "<redacted>" and
//     error text.
func (s ssidSource) resolve() string {
	info := s.wlan()
	if !info.HasInterface {
		return ""
	}
	if v := cleanSSID(info.SSID); v != "" {
		return v
	}
	if !info.Associated && s.auth() == AuthAuthorized {
		return ""
	}
	return s.fallback(info.Interface)
}

func (s ssidSource) fallback(iface string) string {
	if iface == "" {
		iface = wifiInterface(s.run("/usr/sbin/networksetup", "-listallhardwareports"))
	}
	if iface == "" {
		return ""
	}
	if v := parseSummarySSID(s.run("/usr/sbin/ipconfig", "getsummary", iface)); v != "" {
		return v
	}
	return parseAirportNetwork(s.run("/usr/sbin/networksetup", "-getairportnetwork", iface))
}

func run(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// cleanSSID rejects values that are not a plausible SSID: empty, the
// "<redacted>" placeholder macOS substitutes without Location access, or
// anything longer than the 802.11 limit of 32 bytes (error text).
func cleanSSID(v string) string {
	if strings.TrimSpace(v) == "" || len(v) > 32 {
		return ""
	}
	if strings.EqualFold(v, "<redacted>") || strings.EqualFold(v, "redacted") {
		return ""
	}
	return v
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
		return cleanSSID(val)
	}
	return ""
}

// parseAirportNetwork extracts the name from `networksetup
// -getairportnetwork <if>` output ("Current Wi-Fi Network: <name>").
// "You are not associated…", power-off notices, errors and redacted values
// yield "".
func parseAirportNetwork(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"Current Wi-Fi Network:", "Current AirPort Network:"} {
			if val, ok := strings.CutPrefix(line, prefix); ok {
				return cleanSSID(strings.TrimSpace(val))
			}
		}
	}
	return ""
}
