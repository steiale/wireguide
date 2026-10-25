package network

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// Absolute paths for every system tool this package runs. The helper runs as
// root; resolving bare names via PATH would let an inherited/polluted PATH
// substitute a different binary.
const (
	cmdIfconfig     = "/sbin/ifconfig"
	cmdRoute        = "/sbin/route"
	cmdNetstat      = "/usr/sbin/netstat"
	cmdNetworksetup = "/usr/sbin/networksetup"
	cmdDscacheutil  = "/usr/bin/dscacheutil"
	cmdKillall      = "/usr/bin/killall"
)

// DarwinManager implements NetworkManager for macOS, modeled after wg-quick's
// darwin.bash script (github.com/WireGuard/wireguard-tools/src/wg-quick/darwin.bash).
type DarwinManager struct {
	mu sync.Mutex

	// Endpoint bypass route state — tracked for cleanup.
	bypassEndpoints []string // IPs we added host routes for

	// Reapply context — stashed during Connect so the route monitor can
	// re-run bypass/MTU on network changes without needing a config reference.
	lastIface     string
	lastEndpoints []string
	lastMTU       int
	// lastGatewayV4/V6 are the gateways our bypass routes point at. reapply()
	// only rebuilds them when the live gateway differs: route events fire
	// constantly (including for our own `route add`), and a needless
	// delete+re-add briefly loops WG packets through the tunnel.
	lastGatewayV4 string
	lastGatewayV6 string
	// lastHasV4Default/V6Default remember whether AddRoutes hijacked the
	// default route for each address family. reapply() uses these to skip
	// bypass routes for families that weren't actually hijacked.
	lastHasV4Default bool
	lastHasV6Default bool
	// lastUpstreamIface is the physical interface (e.g. en0, en5) cached
	// before split routes are installed. Used by addBypassForIP to pin
	// bypass routes with -ifscope, preventing flapping on dual-network setups.
	// Only populated when pinInterface is true.
	lastUpstreamIface string
	// pinInterface controls whether bypass routes use -ifscope to pin
	// to the upstream interface. Disabled by default.
	pinInterface bool

	// Route monitor (wg-quick monitor_daemon equivalent): started for full
	// tunnels and whenever DNS is overridden.
	monitor *routeMonitor
}

// SetPinInterface enables or disables -ifscope bypass route pinning.
func (m *DarwinManager) SetPinInterface(enabled bool) {
	m.mu.Lock()
	m.pinInterface = enabled
	if !enabled {
		m.lastUpstreamIface = ""
	}
	m.mu.Unlock()
	slog.Info("pin interface toggled", "enabled", enabled)
}

func NewPlatformManager() NetworkManager {
	return &DarwinManager{}
}

// AssignAddress uses wg-quick's form: `ifconfig <if> inet <ip/cidr> <ip> alias`.
// For IPv6: `ifconfig <if> inet6 <ip/cidr> alias` (no netmask).
func (m *DarwinManager) AssignAddress(ifaceName string, addresses []string) error {
	for _, addr := range addresses {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			return fmt.Errorf("invalid address %q: %w", addr, err)
		}
		if ip.To4() != nil {
			// IPv4: ifconfig <if> inet <cidr> <ip> alias
			if err := run(cmdIfconfig, ifaceName, "inet", addr, ip.String(), "alias"); err != nil {
				return fmt.Errorf("assigning address %s: %w", addr, err)
			}
		} else {
			// IPv6: ifconfig <if> inet6 <cidr> alias
			if err := run(cmdIfconfig, ifaceName, "inet6", addr, "alias"); err != nil {
				return fmt.Errorf("assigning address %s: %w", addr, err)
			}
		}
	}
	return nil
}

// SetMTU uses dynamic detection (wg-quick algorithm): default interface MTU
// minus 80 bytes (40 IPv6 + 8 UDP + 32 WireGuard header overhead).
// Falls back to 1420 if detection fails.
func (m *DarwinManager) SetMTU(ifaceName string, mtu int) error {
	if mtu <= 0 {
		// Auto-detect from default interface
		defaultIf := getDefaultInterface()
		upstreamMTU := 1500
		if defaultIf != "" {
			if v := getInterfaceMTU(defaultIf); v > 0 {
				upstreamMTU = v
			}
		}
		mtu = upstreamMTU - 80
		if mtu < 1280 { // IPv6 minimum
			mtu = 1280
		}
	}
	// Idempotent: skip ifconfig if the interface already has the target MTU.
	// wg-quick's set_mtu_up performs the same check.
	if current := getInterfaceMTU(ifaceName); current == mtu {
		m.mu.Lock()
		m.lastMTU = mtu
		m.mu.Unlock()
		return nil
	}
	if err := run(cmdIfconfig, ifaceName, "mtu", fmt.Sprintf("%d", mtu)); err != nil {
		return err
	}
	m.mu.Lock()
	m.lastMTU = mtu
	m.mu.Unlock()
	return nil
}

func (m *DarwinManager) BringUp(ifaceName string) error {
	return run(cmdIfconfig, ifaceName, "up")
}

// AddRoutes installs routes for AllowedIPs. For /0 (full tunnel) it uses
// the split-route trick + endpoint bypass. Routes are added longest-prefix
// first to avoid transient conflicts (wg-quick's sort -nr -k 2 -t /).
func (m *DarwinManager) AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpoints []string, tableCfg string) error {
	if strings.EqualFold(tableCfg, "off") {
		slog.Info("Table=off: skipping route installation", "interface", ifaceName)
		return nil
	}
	// Sort by prefix length descending (longest first)
	sorted := sortAllowedIPs(allowedIPs)

	hasV4Default := false
	hasV6Default := false
	for _, cidr := range sorted {
		isV6 := strings.Contains(cidr, ":")
		if cidr == "0.0.0.0/0" {
			hasV4Default = true
			continue
		}
		if cidr == "::/0" {
			hasV6Default = true
			continue
		}
		// Non-default route: skip if already pointing at this interface (idempotent)
		family := "-inet"
		if isV6 {
			family = "-inet6"
		}
		if existing, _ := runOut(cmdRoute, "-n", "get", family, cidr); routeUsesInterface(existing, ifaceName) {
			continue
		}
		if err := run(cmdRoute, "-q", "-n", "add", family, cidr, "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding route %s: %w", cidr, err)
		}
	}

	// Cache the upstream interface BEFORE installing split routes — after
	// split routes, route-get would return utun instead of the physical iface.
	// Only when pinInterface is enabled (dual-network stability).
	m.mu.Lock()
	pin := m.pinInterface
	m.mu.Unlock()
	if pin {
		upstreamIface := getDefaultInterface()
		m.mu.Lock()
		m.lastUpstreamIface = upstreamIface
		m.mu.Unlock()
	}

	// Install default routes using the split trick
	if hasV4Default {
		if err := run(cmdRoute, "-q", "-n", "add", "-inet", "0.0.0.0/1", "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding 0.0.0.0/1: %w", err)
		}
		if err := run(cmdRoute, "-q", "-n", "add", "-inet", "128.0.0.0/1", "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding 128.0.0.0/1: %w", err)
		}
	}
	if hasV6Default {
		if err := run(cmdRoute, "-q", "-n", "add", "-inet6", "::/1", "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding ::/1: %w", err)
		}
		if err := run(cmdRoute, "-q", "-n", "add", "-inet6", "8000::/1", "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding 8000::/1: %w", err)
		}
	}

	// Add endpoint bypass routes ONLY for the families whose default route
	// we actually hijacked. If a peer endpoint is IPv6 but AllowedIPs only
	// contains 0.0.0.0/0 (IPv4-only full tunnel), the IPv6 default route is
	// untouched — WG packets to the IPv6 peer still flow naturally through
	// the original IPv6 gateway, so NO bypass is needed (and adding one
	// would blackhole a perfectly good path).
	//
	// `endpoints` here are ALREADY-RESOLVED IP LITERALS — the caller
	// (connect_phases) resolved them via the wireguard-go engine at a
	// moment where the tunnel routes were not yet in place. We must never
	// DNS-resolve here, because by this point the /1 split routes above
	// would route the DNS query back through utun, creating a loop.
	//
	// Cache the upstream gateway per family once — one netstat call per
	// family instead of one per endpoint IP.
	var gwV4, gwV6 string
	var gwV4Err, gwV6Err error
	if hasV4Default {
		gwV4, gwV4Err = getDefaultGatewayFor(false)
	}
	if hasV6Default {
		gwV6, gwV6Err = getDefaultGatewayFor(true)
	}
	for _, ipStr := range endpoints {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			slog.Warn("skipping invalid endpoint IP", "ip", ipStr)
			continue
		}
		// Only bypass this endpoint if its family is actually hijacked.
		// See comment above — mis-bypassing a v6 endpoint on a v4-only
		// hijack would blackhole an otherwise-working path.
		isV6 := ip.To4() == nil
		if isV6 && !hasV6Default {
			continue
		}
		if !isV6 && !hasV4Default {
			continue
		}
		if err := m.addBypassForIP(ipStr, gwV4, gwV6, gwV4Err, gwV6Err); err != nil {
			slog.Warn("endpoint bypass route failed", "ip", ipStr, "error", err)
		}
	}

	// Snapshot the current upstream gateway so reapply() can detect genuine
	// changes (Wi-Fi switch etc.) and ignore spurious RTM events.
	currentV4, _ := getDefaultGatewayFor(false)
	currentV6, _ := getDefaultGatewayFor(true)

	// Stash context for reapply on network changes.
	m.mu.Lock()
	m.lastIface = ifaceName
	m.lastEndpoints = append([]string(nil), endpoints...)
	m.lastHasV4Default = hasV4Default
	m.lastHasV6Default = hasV6Default
	m.lastGatewayV4 = currentV4
	m.lastGatewayV6 = currentV6
	m.mu.Unlock()

	// Full tunnels need the monitor so a network switch re-points the
	// endpoint bypass routes at the new gateway (wg-quick's monitor_daemon).
	if fullTunnel {
		m.startMonitor()
	}

	return nil
}

// startMonitor starts the route monitor after a 2s delay, so the route
// events from our own `route add` calls don't trigger a reapply during the
// handshake window. Idempotent.
func (m *DarwinManager) startMonitor() {
	m.mu.Lock()
	if m.monitor == nil {
		m.monitor = newRouteMonitor(m.reapply)
	}
	mon := m.monitor
	m.mu.Unlock()
	go func() {
		time.Sleep(2 * time.Second)
		mon.Start()
	}()
}

// reapply runs on route-monitor events and re-does what depends on the
// network: DNS (only if drifted), and bypass routes + MTU only when the
// gateway or the peer endpoints actually changed, since route events are
// mostly noise and a needless rebuild briefly loops WG packets.
func (m *DarwinManager) reapply() {
	// macOS can rewrite DNS when switching network services.
	reapplyDNSIfDrifted()

	m.mu.Lock()
	iface := m.lastIface
	oldEndpoints := append([]string(nil), m.lastEndpoints...)
	mtu := m.lastMTU
	prevV4 := m.lastGatewayV4
	prevV6 := m.lastGatewayV6
	hasV4 := m.lastHasV4Default
	hasV6 := m.lastHasV6Default
	m.mu.Unlock()

	if iface == "" {
		return
	}

	// wg-quick's set_endpoint_direct_route re-reads endpoints from
	// `wg show <iface> endpoints` on every RTM event, because wireguard-go
	// can roam to a different endpoint IP after a handshake. We do the
	// same via wgctrl so bypass routes track the actual peer endpoint.
	liveEndpoints := collectLiveEndpoints(iface)
	if len(liveEndpoints) == 0 {
		// Interface may be gone — monitor loop will break on the next
		// ifconfig check. Use cached endpoints as fallback.
		liveEndpoints = oldEndpoints
	}

	// Probe the current upstream gateway for each family. These values are
	// reused below when re-installing bypass routes, avoiding a redundant
	// second pair of netstat calls.
	currentV4, currentV4Err := getDefaultGatewayFor(false)
	currentV6, currentV6Err := getDefaultGatewayFor(true)

	gatewayChanged := currentV4 != prevV4 || currentV6 != prevV6

	// Detect endpoint roaming: compare live endpoints against the set we
	// have bypass routes for. wg-quick diffs old vs new and only touches
	// changed entries; we do the same.
	endpointsChanged := !stringSetEqual(oldEndpoints, liveEndpoints)

	needBypassUpdate := (hasV4 || hasV6) && (gatewayChanged || endpointsChanged)

	if !needBypassUpdate {
		return
	}

	slog.Info("route monitor: reapplying bypass routes",
		"iface", iface,
		"gateway_changed", gatewayChanged,
		"endpoints_changed", endpointsChanged,
		"prev_v4", prevV4, "current_v4", currentV4,
		"prev_v6", prevV6, "current_v6", currentV6,
		"old_endpoints", oldEndpoints, "live_endpoints", liveEndpoints)

	// Build sets for diffing (mirrors wg-quick's old_endpoints / ENDPOINTS logic).
	oldSet := make(map[string]bool, len(oldEndpoints))
	for _, ep := range oldEndpoints {
		oldSet[ep] = true
	}
	newSet := make(map[string]bool, len(liveEndpoints))
	for _, ep := range liveEndpoints {
		newSet[ep] = true
	}

	// If gateway changed, delete ALL old bypass routes (wg-quick: remove_all_old=1).
	// If only endpoints changed, delete only endpoints no longer in the live set.
	m.mu.Lock()
	oldBypass := m.bypassEndpoints
	m.bypassEndpoints = nil
	m.mu.Unlock()

	for _, ip := range oldBypass {
		shouldDelete := gatewayChanged || !newSet[ip]
		if !shouldDelete {
			// Still current — keep it in the bypass list without re-adding.
			m.mu.Lock()
			m.bypassEndpoints = append(m.bypassEndpoints, ip)
			m.mu.Unlock()
			continue
		}
		family := "-inet"
		if strings.Contains(ip, ":") {
			family = "-inet6"
		}
		_ = run(cmdRoute, "-q", "-n", "delete", family, ip)
	}

	// Reuse the gateways already probed above — no need for a second pair
	// of netstat calls. If the gateway changed between the probe and now
	// (extremely unlikely), the next RTM event will trigger another reapply.
	newGwV4, newGwV4Err := currentV4, currentV4Err
	newGwV6, newGwV6Err := currentV6, currentV6Err

	// Add bypass routes for endpoints that need (re-)installation:
	// - If gateway changed: all live endpoints (they were all deleted above).
	// - If only endpoints changed: only newly appeared endpoints.
	for _, ipStr := range liveEndpoints {
		if ipStr == "" {
			continue
		}
		if !gatewayChanged && oldSet[ipStr] {
			// Gateway didn't change and this endpoint already had a valid
			// bypass route (preserved above). Skip.
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		isV6 := ip.To4() == nil
		if isV6 && !hasV6 {
			continue
		}
		if !isV6 && !hasV4 {
			continue
		}
		if err := m.addBypassForIP(ipStr, newGwV4, newGwV6, newGwV4Err, newGwV6Err); err != nil {
			slog.Warn("reapply: bypass failed", "ip", ipStr, "error", err)
		}
	}

	// Refresh the upstream interface for -ifscope pinning (netstat outside
	// the lock).
	m.mu.Lock()
	pinIface := m.pinInterface
	m.mu.Unlock()
	newUpstreamIface := ""
	if pinIface {
		newUpstreamIface = getDefaultInterface()
	}
	m.mu.Lock()
	m.lastEndpoints = append([]string(nil), liveEndpoints...)
	m.lastGatewayV4 = newGwV4
	m.lastGatewayV6 = newGwV6
	m.lastUpstreamIface = newUpstreamIface
	m.mu.Unlock()

	if mtu > 0 {
		if current := getInterfaceMTU(iface); current != mtu && current > 0 {
			_ = run(cmdIfconfig, iface, "mtu", fmt.Sprintf("%d", mtu))
		}
	}
}

// collectLiveEndpoints reads the current peer endpoint IPs from the WireGuard
// interface via wgctrl, mirroring wg-quick's `wg show $REAL_INTERFACE endpoints`.
// Returns deduplicated IP strings (no port). Returns nil on any error.
func collectLiveEndpoints(ifaceName string) []string {
	client, err := wgctrl.New()
	if err != nil {
		slog.Debug("collectLiveEndpoints: wgctrl.New failed", "error", err)
		return nil
	}
	defer client.Close()

	dev, err := client.Device(ifaceName)
	if err != nil {
		slog.Debug("collectLiveEndpoints: Device() failed", "iface", ifaceName, "error", err)
		return nil
	}

	seen := make(map[string]bool)
	var eps []string
	for _, peer := range dev.Peers {
		if peer.Endpoint == nil {
			continue
		}
		ip := peer.Endpoint.IP.String()
		if !seen[ip] {
			seen[ip] = true
			eps = append(eps, ip)
		}
	}
	return eps
}

// stringSetEqual returns true if two string slices contain the same elements
// (order-independent).
func stringSetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]int, len(a))
	for _, s := range a {
		set[s]++
	}
	for _, s := range b {
		set[s]--
		if set[s] < 0 {
			return false
		}
	}
	return true
}

// addBypassForIP installs a host route for one already-resolved peer endpoint
// IP, pointing at the upstream default gateway. Without this, encrypted WG
// packets destined for the peer would match the /1 split routes and loop
// back through the tunnel itself.
//
// Gateways are passed in (not resolved here) so the caller can make a single
// netstat call for all IPs in a batch — one per family instead of one per IP.
//
// If the gateway probe failed for a given family, we fall back to wg-quick's
// behaviour of installing a blackhole route, which breaks the loop while
// clearly signalling to the user that handshake is impossible in this state.
func (m *DarwinManager) addBypassForIP(ipStr, gwV4, gwV6 string, gwV4Err, gwV6Err error) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid endpoint IP %q", ipStr)
	}
	isV6 := ip.To4() == nil

	var gw string
	var gwErr error
	family := "-inet"
	if isV6 {
		gw = gwV6
		gwErr = gwV6Err
		family = "-inet6"
	} else {
		gw = gwV4
		gwErr = gwV4Err
	}

	recordBypass := func() {
		m.mu.Lock()
		m.bypassEndpoints = append(m.bypassEndpoints, ipStr)
		m.mu.Unlock()
	}

	if gwErr != nil || gw == "" {
		// No usable upstream gateway → install a blackhole so encrypted WG
		// traffic to this peer doesn't loop through the tunnel.
		loopback := "127.0.0.1"
		if isV6 {
			loopback = "::1"
		}
		_ = run(cmdRoute, "-q", "-n", "add", family, ipStr, loopback, "-blackhole")
		recordBypass()
		return nil
	}

	// Use the cached upstream interface to pin the bypass route with
	// -ifscope. This prevents macOS from flapping between WiFi and
	// Ethernet when both are active.
	m.mu.Lock()
	iface := m.lastUpstreamIface
	m.mu.Unlock()

	// Try `route add` first, fall back to `route change` if the kernel
	// already has a route for this host (common when reconnecting).
	if iface != "" {
		if err := run(cmdRoute, "-q", "-n", "add", family, ipStr, "-gateway", gw, "-ifscope", iface); err != nil {
			if err2 := run(cmdRoute, "-q", "-n", "change", family, ipStr, "-gateway", gw, "-ifscope", iface); err2 != nil {
				// Fallback: try without -ifscope in case the OS rejects it
				slog.Debug("ifscope route failed, falling back to unscoped", "ip", ipStr, "iface", iface)
				if err3 := run(cmdRoute, "-q", "-n", "add", family, ipStr, "-gateway", gw); err3 != nil {
					if err4 := run(cmdRoute, "-q", "-n", "change", family, ipStr, "-gateway", gw); err4 != nil {
						return fmt.Errorf("bypass route %s via %s (ifscope %s failed, unscoped also failed): %v", ipStr, gw, iface, err4)
					}
				}
			}
		}
	} else {
		if err := run(cmdRoute, "-q", "-n", "add", family, ipStr, "-gateway", gw); err != nil {
			if err2 := run(cmdRoute, "-q", "-n", "change", family, ipStr, "-gateway", gw); err2 != nil {
				return fmt.Errorf("bypass route %s via %s: add=%v, change=%v", ipStr, gw, err, err2)
			}
		}
	}
	recordBypass()
	return nil
}

// deleteInterfaceRoutes walks netstat for the given family and deletes
// every route whose interface (Netif column) matches ifaceName.
// Also handles the wg-quick IPv6 edge case where Netif=lo0 but Gateway=utunN.
func (m *DarwinManager) deleteInterfaceRoutes(ifaceName, family string) {
	out, err := runOut(cmdNetstat, "-nr", "-f", family)
	if err != nil {
		return
	}
	// Parse header to find Destination / Gateway / Netif column positions.
	netifIdx, destIdx, gwIdx := -1, -1, -1
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if netifIdx < 0 {
			// Look for header row
			for i, f := range fields {
				switch f {
				case "Destination":
					destIdx = i
				case "Gateway":
					gwIdx = i
				case "Netif":
					netifIdx = i
				}
			}
			continue
		}
		// Require ALL three columns to be in range before indexing, not just
		// Netif — a malformed header could leave destIdx or gwIdx pointing
		// past the line and crash on field access.
		maxIdx := netifIdx
		if destIdx > maxIdx {
			maxIdx = destIdx
		}
		if gwIdx > maxIdx {
			maxIdx = gwIdx
		}
		if len(fields) <= maxIdx || destIdx < 0 || gwIdx < 0 {
			continue
		}
		dest := fields[destIdx]
		gw := fields[gwIdx]
		netif := fields[netifIdx]

		// Match: Netif is our interface, OR (IPv6 only) Netif is lo* and Gateway is our interface
		match := netif == ifaceName
		if !match && family == "inet6" && strings.HasPrefix(netif, "lo") && gw == ifaceName {
			match = true
		}
		if !match {
			continue
		}

		// Use "default" directly in route delete — macOS `route` understands
		// the keyword and it avoids ambiguity with explicit CIDR notation.
		// No translation needed.
		famFlag := "-inet"
		if family == "inet6" {
			famFlag = "-inet6"
		}
		_ = run(cmdRoute, "-q", "-n", "delete", famFlag, dest)
	}
}

// routeUsesInterface checks `route get` output for an exact match on the
// interface field. Prevents false matches between utun3 / utun33.
func routeUsesInterface(routeOutput []byte, ifaceName string) bool {
	for _, line := range strings.Split(string(routeOutput), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			return name == ifaceName
		}
	}
	return false
}

// Cleanup undoes everything this manager set up for ifaceName: stops the
// route monitor (waiting out any in-flight reapply), deletes every route via
// the interface (wg-quick's netstat walk) and our endpoint bypass routes, and
// releases its DNS hold. Also used by crash recovery with a fresh manager.
func (m *DarwinManager) Cleanup(ifaceName string) error {
	m.mu.Lock()
	mon := m.monitor
	m.mu.Unlock()
	if mon != nil {
		mon.Stop()
	}
	_ = m.RestoreDNS(ifaceName)
	m.deleteInterfaceRoutes(ifaceName, "inet")
	m.deleteInterfaceRoutes(ifaceName, "inet6")

	m.mu.Lock()
	bypass := m.bypassEndpoints
	m.bypassEndpoints = nil
	m.lastIface = ""
	m.lastEndpoints = nil
	m.lastGatewayV4, m.lastGatewayV6 = "", ""
	m.lastHasV4Default, m.lastHasV6Default = false, false
	m.mu.Unlock()

	for _, ip := range bypass {
		family := "-inet"
		if strings.Contains(ip, ":") {
			family = "-inet6"
		}
		_ = run(cmdRoute, "-q", "-n", "delete", family, ip)
	}
	return nil
}

// --- helpers ---

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	// LC_ALL/LANG affect POSIX tools' own output, but networksetup and
	// friends are Cocoa/CoreFoundation tools that localize via
	// AppleLanguages instead — this does NOT make their English sentinel
	// strings ("There aren't any DNS Servers...") reliable to match on.
	// getCurrentDNS/getCurrentSearchDomains parse locale-independently
	// instead (filtering by whether a line looks like an IP/hostname).
	// Set anyway in case any other command run through here is a real
	// POSIX tool that does honor it. wg-quick sets this for the same
	// reason at its script's top.
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runOut runs a command with LC_ALL=C and returns combined output.
// Use for commands where we parse the output.
func runOut(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	return cmd.CombinedOutput()
}

// getDefaultGatewayFor returns the IPv4 or IPv6 default gateway, skipping
// link-local entries (link#N) per wg-quick's collect_gateways.
func getDefaultGatewayFor(ipv6 bool) (string, error) {
	family := "inet"
	if ipv6 {
		family = "inet6"
	}
	out, err := runOut(cmdNetstat, "-nr", "-f", family)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] != "default" {
			continue
		}
		gw := fields[1]
		// Skip link-local defaults (point-to-point with no gateway IP)
		if strings.HasPrefix(gw, "link#") {
			continue
		}
		return gw, nil
	}
	return "", fmt.Errorf("no default gateway for %s", family)
}

// getDefaultInterface returns the name of the default route's interface
// by parsing the netstat header to locate the Netif column, then scanning
// for the `default` row. Dynamic header parsing handles column-order
// differences across macOS versions; the previous "first lowercase field"
// heuristic returned `awdl0` (AirDrop) instead of `en0` on some machines.
func getDefaultInterface() string {
	out, err := runOut(cmdNetstat, "-nr", "-f", "inet")
	if err != nil {
		return ""
	}
	netifIdx, destIdx := -1, -1
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if netifIdx < 0 {
			for i, f := range fields {
				switch f {
				case "Destination":
					destIdx = i
				case "Netif":
					netifIdx = i
				}
			}
			continue
		}
		maxIdx := netifIdx
		if destIdx > maxIdx {
			maxIdx = destIdx
		}
		if destIdx < 0 || netifIdx < 0 || len(fields) <= maxIdx {
			continue
		}
		if fields[destIdx] == "default" {
			return fields[netifIdx]
		}
	}
	return ""
}

// getInterfaceMTU reads the MTU from ifconfig output.
func getInterfaceMTU(ifaceName string) int {
	out, err := runOut(cmdIfconfig, ifaceName)
	if err != nil {
		return 0
	}
	// Format includes "mtu 1500"
	idx := strings.Index(string(out), "mtu ")
	if idx < 0 {
		return 0
	}
	rest := string(out)[idx+4:]
	var mtu int
	fmt.Sscanf(rest, "%d", &mtu)
	return mtu
}

// getAllNetworkServices returns all network services, including disabled ones.
// wg-quick includes disabled services (strips the "*" prefix) so DNS is
// applied/restored uniformly regardless of current enabled state.
func getAllNetworkServices() []string {
	out, err := runOut(cmdNetworksetup, "-listallnetworkservices")
	if err != nil {
		return nil
	}
	var services []string
	firstLine := true
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if firstLine {
			// First non-empty line is the header ("An asterisk...")
			firstLine = false
			continue
		}
		// Strip leading "*" from disabled services (don't skip them)
		if strings.HasPrefix(line, "*") {
			line = strings.TrimSpace(line[1:])
		}
		if line != "" {
			services = append(services, line)
		}
	}
	return services
}

// getCurrentDNS returns the DNS servers currently configured on service.
// networksetup's "no servers configured" response is a localized English
// sentence ("There aren't any DNS Servers...") that follows the system's
// AppleLanguages setting — LC_ALL=C (see run()) has no effect on it, since
// this is a Cocoa/CoreFoundation tool, not a POSIX one. Matching that
// sentinel string only works on an English system; on any other locale the
// whole sentence would be treated as a "DNS server" and saved into the
// original-DNS baseline. Instead, keep only lines that actually parse as an
// IP address — locale-independent by construction.
func getCurrentDNS(service string) ([]string, error) {
	out, err := runOut(cmdNetworksetup, "-getdnsservers", service)
	if err != nil {
		return nil, err
	}
	output := strings.TrimSpace(string(out))
	var servers []string
	for _, line := range strings.Split(output, "\n") {
		s := strings.TrimSpace(line)
		if s != "" && net.ParseIP(s) != nil {
			servers = append(servers, s)
		}
	}
	return servers, nil
}

// getCurrentSearchDomains returns the search domains currently configured on
// service. Same locale caveat as getCurrentDNS applies to the "no search
// domains" sentinel — a real search domain never contains whitespace, so
// filtering on that instead of an English string is locale-independent.
func getCurrentSearchDomains(service string) ([]string, error) {
	out, err := runOut(cmdNetworksetup, "-getsearchdomains", service)
	if err != nil {
		return nil, err
	}
	output := strings.TrimSpace(string(out))
	var domains []string
	for _, line := range strings.Split(output, "\n") {
		s := strings.TrimSpace(line)
		if s != "" && !strings.ContainsAny(s, " \t") {
			domains = append(domains, s)
		}
	}
	return domains, nil
}

// sortAllowedIPs sorts CIDRs by prefix length descending (longest first),
// matching wg-quick's `sort -nr -k 2 -t /`. Stable order for determinism.
func sortAllowedIPs(cidrs []string) []string {
	result := make([]string, len(cidrs))
	copy(result, cidrs)

	// Simple insertion sort (lists are small, stability guaranteed)
	for i := 1; i < len(result); i++ {
		cur := result[i]
		curPrefix := prefixLen(cur)
		j := i - 1
		for j >= 0 && prefixLen(result[j]) < curPrefix {
			result[j+1] = result[j]
			j--
		}
		result[j+1] = cur
	}
	return result
}

func prefixLen(cidr string) int {
	idx := strings.Index(cidr, "/")
	if idx < 0 {
		// Bare address without prefix — return 32 for IPv4, 128 for IPv6
		if strings.Contains(cidr, ":") {
			return 128
		}
		return 32
	}
	var n int
	fmt.Sscanf(cidr[idx+1:], "%d", &n)
	return n
}
