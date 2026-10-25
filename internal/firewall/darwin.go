package firewall

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// anchorName must sit under "com.apple/" (slash): macOS pf.conf only
// evaluates `anchor "com.apple/*"`, so any other name loads but never filters.
const anchorName = "com.apple/wireguide"

// legacyDNSAnchor held DNS protection rules in older helpers. Flushed on
// teardown so an upgrade can't leave orphaned rules behind.
const legacyDNSAnchor = anchorName + "/dns"

// pfctlPath is absolute: the helper runs as root, never resolve via PATH.
const pfctlPath = "/sbin/pfctl"

// savedPfStateFile records whether pf was enabled before we first loaded
// rules, so crash recovery can restore it.
const savedPfStateFile = "/Library/Application Support/lockplus/pf-was-enabled"

// DarwinFirewall implements FirewallManager with a single pf anchor.
type DarwinFirewall struct {
	mu           sync.Mutex // serializes Apply/Cleanup, including pfctl calls
	active       bool       // our rules are loaded and pf is under our control
	pfWasEnabled bool
}

func NewPlatformFirewall() FirewallManager {
	return &DarwinFirewall{}
}

// Apply implements FirewallManager.
func (f *DarwinFirewall) Apply(rs Ruleset) error {
	rules, err := BuildRules(rs)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if rules == "" {
		f.teardownLocked()
		return nil
	}
	firstUse := !f.active
	if firstUse {
		f.pfWasEnabled = isPfEnabled()
		if err := persistPfEnabledState(f.pfWasEnabled); err != nil {
			slog.Warn("failed to persist pf enabled state", "error", err)
		}
	}
	if err := loadAnchorRules(anchorName, rules); err != nil {
		if firstUse {
			removePfStateFile()
		}
		return fmt.Errorf("loading pf rules: %w", err)
	}
	// Mark active before enabling pf so a later teardown flushes the loaded
	// rules even if enabling fails.
	f.active = true
	if err := enablePf(); err != nil {
		return fmt.Errorf("pf rules loaded but pf could not be enabled: %w", err)
	}
	slog.Info("firewall rules applied", "kill_switch", rs.KillSwitch,
		"dns_protection", rs.enforcesDNS(), "tunnels", len(rs.Tunnels))
	return nil
}

// Cleanup implements FirewallManager.
func (f *DarwinFirewall) Cleanup() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.teardownLocked()
	return nil
}

func (f *DarwinFirewall) teardownLocked() {
	if !f.active {
		return
	}
	if err := flushAllAnchors(); err != nil {
		slog.Warn("flush pf anchors failed", "error", err)
	}
	if !f.pfWasEnabled {
		if err := disablePf(); err != nil {
			slog.Warn("pfctl -d failed", "error", err)
		}
	}
	removePfStateFile()
	f.active = false
	slog.Info("firewall rules removed")
}

// RecoverStaleState removes pf state left by a previous helper process that
// exited without Cleanup (SIGKILL, crash). Call once at startup, after the
// IPC socket is bound (so a second instance never flushes a live helper's
// rules) and before any request is served.
func RecoverStaleState() {
	if err := flushAllAnchors(); err != nil {
		slog.Warn("startup: flush stale pf anchors failed", "error", err)
	}
	data, err := os.ReadFile(savedPfStateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("startup: read pf state file failed", "path", savedPfStateFile, "error", err)
		}
		return
	}
	// "0": pf was off before we touched it, turn it back off.
	if strings.TrimSpace(string(data)) == "0" {
		if err := disablePf(); err != nil {
			slog.Warn("startup: pfctl -d failed", "error", err)
		} else {
			slog.Info("startup: pf disabled (was off before LockPlus enabled it)")
		}
	}
	removePfStateFile()
}

// --- pf helpers ---

func loadAnchorRules(anchor, rules string) error {
	cmd := exec.Command(pfctlPath, "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -a %s -f -: %w (%s)", anchor, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isPfEnabled parses `pfctl -si`; LC_ALL=C keeps the "Status: Enabled"
// sentinel in English.
func isPfEnabled() bool {
	cmd := exec.Command(pfctlPath, "-si")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: Enabled")
}

func enablePf() error {
	out, err := exec.Command(pfctlPath, "-e").CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if strings.Contains(outStr, "already enabled") {
			return nil
		}
		return fmt.Errorf("pfctl -e: %w (%s)", err, outStr)
	}
	return nil
}

func disablePf() error {
	out, err := exec.Command(pfctlPath, "-d").CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if strings.Contains(outStr, "already disabled") {
			return nil
		}
		return fmt.Errorf("pfctl -d: %w (%s)", err, outStr)
	}
	return nil
}

// persistPfEnabledState writes "1" or "0" for crash recovery.
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

func removePfStateFile() {
	if err := os.Remove(savedPfStateFile); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove pf state file", "path", savedPfStateFile, "error", err)
	}
}

// flushAllAnchors flushes our anchor and the legacy DNS sub-anchor.
func flushAllAnchors() error {
	var errs []string
	for _, args := range [][]string{
		{"-a", legacyDNSAnchor, "-F", "rules"},
		{"-a", anchorName, "-Fa"},
	} {
		if out, err := exec.Command(pfctlPath, args...).CombinedOutput(); err != nil {
			errs = append(errs, fmt.Sprintf("pfctl %s: %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out))))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("flushAllAnchors: %s", strings.Join(errs, "; "))
	}
	return nil
}
