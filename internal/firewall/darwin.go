//go:build darwin

package firewall

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// validIfaceName matches typical macOS interface names like utun4, en0, lo0.
var validIfaceName = regexp.MustCompile(`^[a-z]+[0-9]+$`)

// anchorName is the pf anchor where WireGuide loads its rules.  macOS ships
// with `anchor "com.apple/*" all` in pf.conf — note the SLASH, not a dot.
// That wildcard only evaluates anchors nested under the "com.apple" anchor
// point (e.g. "com.apple/200.AirDrop"), so the anchor name here MUST use a
// slash too, or pf loads our rules successfully into a completely
// unreferenced top-level anchor that the kernel never evaluates — pfctl
// calls all report success, IsKillSwitchEnabled() returns true, but zero
// packets are ever actually filtered. Confirmed by inspecting the live
// ruleset (`pfctl -sr` only ever contains `anchor "com.apple/*"`, nothing
// else) — a prior "com.apple.wireguide" (dot) anchor name here was exactly
// this bug: syntactically valid, semantically inert.
const anchorName = "com.apple/wireguide"

// dnsAnchorName is the sub-anchor for DNS protection rules.
const dnsAnchorName = anchorName + "/dns"

// savedPfStateFile persists whether pf was enabled before WireGuide modified
// it, so crash recovery can restore the original enabled/disabled state.
const savedPfStateFile = "/Library/Application Support/lockplus/pf-was-enabled"

// DarwinFirewall implements FirewallManager using macOS pf (packet filter).
//
// All WireGuide rules are loaded into the `com.apple/wireguide` anchor.
// macOS ships with `anchor "com.apple/*" all` in pf.conf, so our anchor
// is automatically evaluated without modifying the main ruleset.
// DNS protection rules live in a sub-anchor `com.apple/wireguide/dns`.
type DarwinFirewall struct {
	// opMu serializes the ENTIRE body of every Enable*/Disable*/Cleanup
	// call against every other one — not just the field reads/writes (see
	// mu below). Without this, e.g. a GUI-initiated DisableKillSwitch and
	// the reconnect monitor's DisableDNSProtection (called back-to-back
	// from suspendFirewall, on a different goroutine) can interleave their
	// pfctl calls: each snapshots the OTHER feature as still active,
	// proceeds on that now-stale assumption, and the result is pf left
	// enabled with orphaned rules while both features report themselves
	// disabled — a worse outcome than either call running to completion
	// alone. Distinct from `mu` because some of these methods call helpers
	// (e.g. snapshotPfStateForFirstUse) that lock `mu` internally —
	// holding `mu` across the whole body would self-deadlock.
	opMu sync.Mutex

	mu                   sync.Mutex
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
	// pfWasEnabled tracks whether pf was already enabled before we started,
	// so we know whether to turn pf back off on disable/cleanup.
	pfWasEnabled bool

	// dnsInterfaceName/dnsServers remember DNS protection's last-applied
	// rule inputs so DisableKillSwitch can re-home them directly into the
	// main anchor if DNS protection is still active when the kill switch
	// is turned off — see DisableKillSwitch's doc comment.
	dnsInterfaceName string
	dnsServers       []string
}

func NewPlatformFirewall() FirewallManager {
	return &DarwinFirewall{}
}

// snapshotPfStateForFirstUse returns the pf-enabled state to persist as
// pfWasEnabled for a pf-controlling feature (kill switch or DNS protection)
// being enabled or refreshed right now. The kill switch and DNS protection
// share the same underlying pfWasEnabled bookkeeping — whichever of the two
// (or a repeated/refresh call to the SAME one) is enabled while the other
// is already active would otherwise read pf's CURRENT state via
// isPfEnabled() (already "on" because the other feature — or an earlier
// call to this one — already turned it on) and clobber the real original
// pre-enable value. So a fresh snapshot is only taken when NEITHER feature
// currently has pf under control; otherwise the existing pfWasEnabled is
// reused untouched.
func (f *DarwinFirewall) snapshotPfStateForFirstUse() bool {
	f.mu.Lock()
	alreadyControllingPf := f.killSwitchEnabled || f.dnsProtectionEnabled
	pfWas := f.pfWasEnabled
	f.mu.Unlock()
	if alreadyControllingPf {
		return pfWas
	}
	pfWas = isPfEnabled()
	if err := persistPfEnabledState(pfWas); err != nil {
		slog.Warn("failed to persist pf enabled state to disk", "error", err)
	}
	return pfWas
}

// EnableKillSwitch loads pf pass/block rules for the currently active
// tunnel(s) at the moment it's called. The caller (internal/helper) is
// responsible for re-invoking this — via Helper.refreshKillSwitchIfEnabled
// — whenever a tunnel connects or disconnects while the kill switch is
// already enabled (WireGuard's handleConnect/handleDisconnect and OpenVPN's
// onActiveChange callback both do), not just on a manual toggle or a
// WireGuard reconnect's suspend/resume cycle. This function itself has no
// notion of "add" or "remove" — every call rebuilds the FULL ruleset from
// whatever the caller currently reports as active.
func (f *DarwinFirewall) EnableKillSwitch(interfaceName string, _ []string, endpoints []string, extra []KillSwitchTunnel) error {
	f.opMu.Lock()
	defer f.opMu.Unlock()
	// M1: Validate interface name. interfaceName may be empty for an
	// OpenVPN-only session (no WireGuard tunnel active) — extra covers that
	// case instead.
	if interfaceName != "" && !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}
	for _, t := range extra {
		if !validIfaceName.MatchString(t.InterfaceName) {
			return fmt.Errorf("invalid interface name %q", t.InterfaceName)
		}
	}
	if interfaceName == "" && len(extra) == 0 {
		return fmt.Errorf("no active tunnel to enable kill switch for")
	}

	// Snapshot pf state so we can restore enabled/disabled on teardown —
	// but only if pf isn't ALREADY under one of our features' control (see
	// snapshotPfStateForFirstUse). This function is also called to REFRESH
	// the ruleset while the kill switch is already on (a tunnel
	// connected/disconnected — see Helper.refreshKillSwitchIfEnabled), and
	// DNS protection may have already turned pf on by itself — either way,
	// re-snapshotting here would read pf's CURRENT (already-on) state and
	// clobber the real original pre-enable value, leaving pf permanently
	// enabled after a later Disable* call on a machine where it was off to
	// begin with.
	pfWas := f.snapshotPfStateForFirstUse()

	// Build kill switch rules — loaded into the anchor, not the main ruleset.
	// macOS ships with `anchor "com.apple/*" all` in pf.conf, so our
	// anchor `com.apple/wireguide` is automatically evaluated without
	// modifying the main ruleset at all.
	var rules strings.Builder
	rules.WriteString("# WireGuide kill switch rules\n")
	rules.WriteString("# Allow loopback\n")
	rules.WriteString("pass quick on lo0 all\n")

	// Allow each WireGuard endpoint (restrict to proto udp + port when available).
	// Without port/protocol restriction, ALL traffic to the endpoint IP bypasses
	// the kill switch, which is a security concern if the WireGuard server runs
	// other services on the same IP.
	for _, ep := range endpoints {
		ip, port, _ := net.SplitHostPort(ep)
		if ip == "" {
			ip = ep // fallback: bare IP without port
		}
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid endpoint IP %q", ip)
		}
		if port != "" {
			fmt.Fprintf(&rules, "pass out quick proto udp to %s port %s\n", ip, port)
		} else {
			// No port info — allow all UDP to this IP (WireGuard is always UDP)
			fmt.Fprintf(&rules, "pass out quick proto udp to %s\n", ip)
		}
	}

	// Allow each additional tunnel's remote (e.g. OpenVPN, which — unlike
	// WireGuard — commonly runs over TCP, so the protocol is explicit per
	// tunnel rather than assumed.
	for _, t := range extra {
		proto := "udp"
		if strings.HasPrefix(t.Proto, "tcp") {
			proto = "tcp"
		}
		for _, ep := range t.Endpoints {
			ip, port, _ := net.SplitHostPort(ep)
			if ip == "" {
				ip = ep
			}
			if ip == "" {
				continue
			}
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid endpoint IP %q", ip)
			}
			// TCP pass rules default to `flags S/SA` (pf.conf(5)) — they only
			// match the initial SYN, not the mid-stream ACK/data packets
			// that make up the rest of an already-established connection.
			// Since the kill switch is enabled AFTER the OpenVPN TCP
			// connection is already up, an S/SA-only rule would let the SYN
			// through (irrelevant, already connected) but block every
			// subsequent packet, stalling the tunnel. `flags any` matches
			// regardless of TCP flags, same as UDP's flagless pass-through.
			flags := ""
			if proto == "tcp" {
				flags = " flags any"
			}
			if port != "" {
				fmt.Fprintf(&rules, "pass out quick proto %s to %s port %s%s\n", proto, ip, port, flags)
			} else {
				fmt.Fprintf(&rules, "pass out quick proto %s to %s%s\n", proto, ip, flags)
			}
		}
	}

	// Allow DHCP (so lease renewal works while kill switch is active)
	rules.WriteString("pass out quick proto udp from any port 68 to any port 67\n")
	// H7: Allow DHCPv6
	rules.WriteString("pass out quick proto udp from any port 546 to any port 547\n")

	// Allow the WireGuard tunnel interface, if one is active.
	if interfaceName != "" {
		fmt.Fprintf(&rules, "pass quick on %s all\n", interfaceName)
	}
	// Allow each additional (e.g. OpenVPN) tunnel's interface.
	for _, t := range extra {
		fmt.Fprintf(&rules, "pass quick on %s all\n", t.InterfaceName)
	}

	// DNS protection sub-anchor — must appear BEFORE the block rules so pf
	// evaluates DNS filtering rules loaded into the sub-anchor.
	//
	// This reference is written INTO the ruleset of anchor `anchorName`
	// itself (see loadAnchorRules(anchorName, ...) below), so per pf.conf(5)
	// it must be a RELATIVE name ("dns"), not the full absolute path — an
	// anchor name without a leading "/" nested inside another anchor's rules
	// resolves relative to that anchor. Using the full `dnsAnchorName`
	// ("com.apple/wireguide/dns") here would have pf look for
	// "com.apple/wireguide/com.apple/wireguide/dns" instead, which doesn't
	// exist, so the DNS sub-anchor's rules would never be reached even once
	// the anchorName fix above makes the parent anchor itself reachable.
	rules.WriteString("anchor \"dns\"\n")

	// Block all other traffic
	rules.WriteString("block drop out all\n")
	rules.WriteString("block drop in all\n")

	// Load rules into the anchor.
	if err := loadAnchorRules(anchorName, rules.String()); err != nil {
		return fmt.Errorf("loading kill switch rules into anchor: %w", err)
	}

	// If DNS protection was already active BEFORE the kill switch, its
	// rules were living directly in the main anchor (see
	// EnableDNSProtection's no-kill-switch path) — which the load above
	// just REPLACED with the kill switch's own ruleset. Re-home them into
	// the sub-anchor the kill switch's ruleset now references (the
	// `anchor "dns"` line above), so DNS protection survives the kill
	// switch being turned on instead of silently losing its rules while
	// still reporting itself enabled — the mirror image of what
	// DisableKillSwitch does when DNS protection outlives the kill switch.
	f.mu.Lock()
	dnsAlreadyActive := f.dnsProtectionEnabled
	dnsIfaceForSubAnchor := f.dnsInterfaceName
	dnsServersForSubAnchor := f.dnsServers
	f.mu.Unlock()
	if dnsAlreadyActive {
		if dnsSubRules, err := buildDNSProtectionRules(dnsIfaceForSubAnchor, dnsServersForSubAnchor); err != nil {
			slog.Warn("EnableKillSwitch: could not rebuild DNS protection rules for the sub-anchor, DNS protection may be left without active rules until re-toggled", "error", err)
		} else if err := loadAnchorRules(dnsAnchorName, dnsSubRules); err != nil {
			slog.Warn("EnableKillSwitch: failed to re-home DNS protection rules into its sub-anchor, DNS protection may be left without active rules until re-toggled", "error", err)
		}
	}

	// Enable pf if not already.
	if err := enablePf(); err != nil {
		slog.Warn("pfctl -e failed", "error", err)
	}

	f.mu.Lock()
	f.pfWasEnabled = pfWas
	f.killSwitchEnabled = true
	f.mu.Unlock()
	slog.Info("kill switch enabled", "interface", interfaceName, "endpoints", len(endpoints))
	return nil
}

// DisableKillSwitch removes the kill switch's pf rules. If DNS protection is
// STILL enabled at this point, its rules are re-homed directly into the main
// anchor (the same way EnableDNSProtection loads them when there's no kill
// switch) instead of being torn down along with everything else — DNS
// protection's rules currently live in the `com.apple/wireguide/dns`
// sub-anchor, reachable only via the `anchor "dns"` reference line INSIDE
// the kill switch's own ruleset (see EnableKillSwitch), which is about to be
// flushed. Without this, disabling the kill switch while DNS protection is
// separately on would silently kill DNS protection's actual filtering while
// it continues to report itself as enabled.
func (f *DarwinFirewall) DisableKillSwitch() error {
	f.opMu.Lock()
	defer f.opMu.Unlock()
	f.mu.Lock()
	pfWas := f.pfWasEnabled
	dnsStillActive := f.dnsProtectionEnabled
	dnsIface := f.dnsInterfaceName
	dnsServers := f.dnsServers
	f.mu.Unlock()

	if dnsStillActive {
		rules, err := buildDNSProtectionRules(dnsIface, dnsServers)
		if err != nil {
			slog.Error("DisableKillSwitch: could not rebuild DNS protection rules — main anchor still holds the kill switch's OLD ruleset, so it keeps enforcing despite reporting disabled (deliberate: failing closed here is safer than flushing to an inconsistent state that would ALSO silently drop DNS protection's rules)", "error", err)
		} else if err := loadAnchorRules(anchorName, rules); err != nil {
			// pfctl -f is atomic (load-or-reject) — a failure here means
			// the main anchor still holds whatever it held before this
			// call, i.e. the kill switch's OLD ruleset, which keeps
			// enforcing despite killSwitchEnabled being set false below.
			// Same fail-closed reasoning as above.
			slog.Error("DisableKillSwitch: failed to re-home DNS protection rules into main anchor — kill switch's old ruleset is still loaded and enforcing despite reporting disabled", "error", err)
		}
		// The DNS sub-anchor is no longer reachable now that the kill
		// switch's own ruleset (which contained the "anchor \"dns\""
		// reference to it) is being removed below — flush it so no
		// orphaned pf state lingers. Harmless: its rules were just
		// re-homed into the main anchor above.
		if out, err := exec.Command("pfctl", "-a", dnsAnchorName, "-F", "rules").CombinedOutput(); err != nil {
			slog.Warn("failed to flush DNS pf anchor", "error", err, "output", strings.TrimSpace(string(out)))
		}
		// Flush only the kill switch's own rules from the main anchor —
		// loadAnchorRules above already replaced them with the DNS-only
		// ruleset, so there's nothing further to remove there. pf itself
		// must stay enabled and pfWasEnabled must NOT be touched: DNS
		// protection still needs pf on, and its own eventual
		// DisableDNSProtection call is what performs the real restore
		// (killSwitchEnabled will be false by then, so it takes the
		// "no kill switch" branch and does its own disablePf()/state-file
		// cleanup correctly).
		f.mu.Lock()
		f.killSwitchEnabled = false
		f.mu.Unlock()
		slog.Info("kill switch disabled (DNS protection still active, pf left enabled)")
		return nil
	}

	// Flush the anchor rules — main ruleset is untouched.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("failed to flush anchor rules", "error", err)
	}

	// If pf was not enabled before we started, disable it now.
	if !pfWas {
		if err := disablePf(); err != nil {
			slog.Warn("pfctl -d failed", "error", err)
		}
	}

	// Clean up persisted state file.
	removePfStateFile()

	f.mu.Lock()
	f.killSwitchEnabled = false
	f.mu.Unlock()
	slog.Info("kill switch disabled")
	return nil
}

// buildDNSProtectionRules constructs the pf rule text for DNS protection:
// pass DNS (tcp+udp/53) through the given interface to each server, block
// everything else. Shared by EnableDNSProtection and DisableKillSwitch's
// DNS-still-active re-home path (see DisableKillSwitch's doc comment).
func buildDNSProtectionRules(interfaceName string, dnsServers []string) (string, error) {
	var dnsRules strings.Builder
	for _, dns := range dnsServers {
		if net.ParseIP(dns) == nil {
			return "", fmt.Errorf("invalid DNS server IP %q", dns)
		}
		// flags any (the tcp half of this {tcp, udp} expansion only —
		// pf ignores it for the udp half): DNS-over-TCP can be a persistent
		// connection (RFC 7766) established before this rule loads, and
		// pf's default TCP flags S/SA only matches a fresh SYN — same
		// reasoning as the OpenVPN kill-switch TCP rules above.
		fmt.Fprintf(&dnsRules, "pass out quick on %s proto {tcp, udp} to %s port 53 flags any\n", interfaceName, dns)
	}
	dnsRules.WriteString("block drop out quick proto {tcp, udp} to any port 53\n")
	return dnsRules.String(), nil
}

func (f *DarwinFirewall) EnableDNSProtection(interfaceName string, dnsServers []string) error {
	f.opMu.Lock()
	defer f.opMu.Unlock()
	if len(dnsServers) == 0 {
		return nil
	}

	// M1: Validate interface name
	if !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}

	dnsRules, err := buildDNSProtectionRules(interfaceName, dnsServers)
	if err != nil {
		return err
	}

	f.mu.Lock()
	ksEnabled := f.killSwitchEnabled
	f.mu.Unlock()

	if ksEnabled {
		// Kill switch is active — its anchor rules already contain a
		// relative `anchor "dns"` reference (resolving to
		// `com.apple/wireguide/dns`), so loading into the sub-anchor
		// works directly.
		if err := loadAnchorRules(dnsAnchorName, dnsRules); err != nil {
			return fmt.Errorf("loading DNS anchor rules: %w", err)
		}
	} else {
		// No kill switch — load DNS rules into the main anchor.
		// macOS evaluates the anchor via the com.apple/* wildcard.
		pfWas := f.snapshotPfStateForFirstUse()

		if err := loadAnchorRules(anchorName, dnsRules); err != nil {
			return fmt.Errorf("loading DNS rules into anchor: %w", err)
		}

		if err := enablePf(); err != nil {
			slog.Warn("pfctl -e failed while enabling DNS protection", "error", err)
		}

		f.mu.Lock()
		f.pfWasEnabled = pfWas
		f.mu.Unlock()
	}

	f.mu.Lock()
	f.dnsProtectionEnabled = true
	f.dnsInterfaceName = interfaceName
	f.dnsServers = dnsServers
	f.mu.Unlock()
	slog.Info("DNS protection enabled", "interface", interfaceName, "dns_servers", dnsServers)
	return nil
}

func (f *DarwinFirewall) DisableDNSProtection() error {
	f.opMu.Lock()
	defer f.opMu.Unlock()
	// Snapshot state under lock.
	f.mu.Lock()
	ksEnabled := f.killSwitchEnabled
	pfWas := f.pfWasEnabled
	f.mu.Unlock()

	if ksEnabled {
		// Kill switch is active — DNS rules are in the sub-anchor, just flush it.
		cmd := exec.Command("pfctl", "-a", dnsAnchorName, "-F", "rules")
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("failed to flush DNS pf anchor", "error", err, "output", strings.TrimSpace(string(out)))
		}
	} else {
		// DNS rules were loaded into the main anchor.  Flush the anchor.
		if err := flushAllAnchors(); err != nil {
			slog.Warn("failed to flush anchor rules", "error", err)
		}

		removePfStateFile()

		if !pfWas {
			if err := disablePf(); err != nil {
				slog.Warn("pfctl -d failed", "error", err)
			}
		}
	}

	f.mu.Lock()
	f.dnsProtectionEnabled = false
	f.dnsInterfaceName = ""
	f.dnsServers = nil
	f.mu.Unlock()
	slog.Info("DNS protection disabled")
	return nil
}

func (f *DarwinFirewall) IsKillSwitchEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killSwitchEnabled
}
func (f *DarwinFirewall) IsDNSProtectionEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dnsProtectionEnabled
}

func (f *DarwinFirewall) Cleanup() error {
	f.opMu.Lock()
	defer f.opMu.Unlock()
	f.mu.Lock()
	dnsActive := f.dnsProtectionEnabled
	ksActive := f.killSwitchEnabled
	pfWas := f.pfWasEnabled
	f.dnsProtectionEnabled = false
	f.killSwitchEnabled = false
	f.mu.Unlock()

	// Flush all anchor rules regardless of what was active.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("cleanup: flush pf anchors failed", "error", err)
	}

	// Restore pf enabled/disabled state if we had anything active.
	if ksActive || dnsActive {
		if !pfWas {
			if err := disablePf(); err != nil {
				slog.Warn("cleanup: pfctl -d failed", "error", err)
			}
		}

		removePfStateFile()
	}

	return nil
}

// --- pf helper functions ---

// loadAnchorRules loads rules into the specified pf anchor.
func loadAnchorRules(anchor, rules string) error {
	cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -a %s -f -: %w (%s)", anchor, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isPfEnabled checks whether pf is currently enabled by parsing `pfctl -si`.
// M5: Force LC_ALL=C/LANG=C so the English "Status: Enabled" sentinel
// matches even when the helper is launched under a non-English locale.
// Without this, on (e.g.) a German macOS install pfctl emits "Status: Aktiviert"
// and we'd silently report pf as disabled.
func isPfEnabled() bool {
	cmd := exec.Command("pfctl", "-si")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	// Look for "Status: Enabled" in the output
	return strings.Contains(string(out), "Status: Enabled")
}

// enablePf enables the pf firewall.
func enablePf() error {
	out, err := exec.Command("pfctl", "-e").CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		// "pf already enabled" is not a real error
		if strings.Contains(outStr, "already enabled") {
			return nil
		}
		return fmt.Errorf("pfctl -e: %w (%s)", err, outStr)
	}
	return nil
}

// disablePf disables the pf firewall.
func disablePf() error {
	out, err := exec.Command("pfctl", "-d").CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if strings.Contains(outStr, "already disabled") {
			return nil
		}
		return fmt.Errorf("pfctl -d: %w (%s)", err, outStr)
	}
	return nil
}

// persistPfEnabledState writes whether pf was enabled to disk for crash
// recovery.  The file contains "1" if enabled, "0" if disabled.
func persistPfEnabledState(enabled bool) error {
	dir := filepath.Dir(savedPfStateFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}
	val := "0"
	if enabled {
		val = "1"
	}
	if err := os.WriteFile(savedPfStateFile, []byte(val), 0600); err != nil {
		return fmt.Errorf("writing %s: %w", savedPfStateFile, err)
	}
	return nil
}

// readPersistedPfState reads the persisted pf enabled state from disk.
// Returns true (enabled) as the safe default if the file can't be read.
func readPersistedPfState() bool {
	data, err := os.ReadFile(savedPfStateFile)
	if err != nil {
		// Default to "was enabled" so we don't accidentally disable pf.
		return true
	}
	return strings.TrimSpace(string(data)) == "1"
}

// removePfStateFile removes the persisted pf state file.
func removePfStateFile() {
	if err := os.Remove(savedPfStateFile); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove pf state file", "path", savedPfStateFile, "error", err)
	}
}

// RecoverSavedRules checks for a persisted pf state file left behind by a
// crash and restores the original pf state by flushing all anchors and
// restoring the pf enabled/disabled state.  Returns true if recovery was
// performed.
func RecoverSavedRules() bool {
	pfWasEnabled := readPersistedPfState()

	// Check if the state file exists — if not, nothing to recover.
	if _, err := os.Stat(savedPfStateFile); err != nil {
		return false
	}

	slog.Info("recovering pf state from crash-recovery file", "pfWasEnabled", pfWasEnabled)

	// Flush all anchor rules.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("recovery: failed to flush anchors", "error", err)
	}

	// Restore pf enabled/disabled state.
	if !pfWasEnabled {
		if err := disablePf(); err != nil {
			slog.Warn("recovery: failed to disable pf", "error", err)
		}
	}

	removePfStateFile()
	slog.Info("pf state restored successfully from crash-recovery file")
	return true
}

// flushAllAnchors flushes all rules from the WireGuide anchors.
func flushAllAnchors() error {
	var errs []string

	// Flush the DNS sub-anchor first.
	if out, err := exec.Command("pfctl", "-a", dnsAnchorName, "-F", "rules").CombinedOutput(); err != nil {
		errs = append(errs, fmt.Sprintf("flush %s: %v (%s)", dnsAnchorName, err, strings.TrimSpace(string(out))))
	}
	// Flush the main anchor (this also covers any rules loaded directly).
	if out, err := exec.Command("pfctl", "-a", anchorName, "-Fa").CombinedOutput(); err != nil {
		errs = append(errs, fmt.Sprintf("flush %s: %v (%s)", anchorName, err, strings.TrimSpace(string(out))))
	}

	if len(errs) > 0 {
		return fmt.Errorf("flushAllAnchors: %s", strings.Join(errs, "; "))
	}
	return nil
}
