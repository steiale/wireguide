package network

import (
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// System DNS (networksetup) is one machine-wide resource shared by every
// tunnel of both protocols. Each tunnel registers its entries as a holder;
// the system always gets the union of all holders, and the user's original
// settings (journaled to disk) come back once the last holder releases.
//
// dnsMu is held for whole operations, including the networksetup calls, so
// the baseline capture can never interleave with another tunnel's override.
var (
	dnsMu          sync.Mutex
	dnsSavedDNS    = make(map[string][]string) // service → original servers
	dnsSavedSearch = make(map[string][]string) // service → original search domains
	dnsHolders     dnsHolderSet
)

// dnsHolderSet maps a holder (interface or tunnel name) to its DNS entries,
// newest holder first so the most recently connected tunnel's resolver is
// primary.
type dnsHolderSet struct {
	order   []string
	entries map[string][]string
}

func (s *dnsHolderSet) len() int { return len(s.order) }

func (s *dnsHolderSet) get(holder string) ([]string, bool) {
	e, ok := s.entries[holder]
	return e, ok
}

// set records entries for holder; a new holder goes to the front.
func (s *dnsHolderSet) set(holder string, entries []string) {
	if s.entries == nil {
		s.entries = make(map[string][]string)
	}
	if _, ok := s.entries[holder]; !ok {
		s.order = append([]string{holder}, s.order...)
	}
	s.entries[holder] = slices.Clone(entries)
}

// remove reports whether holder was present.
func (s *dnsHolderSet) remove(holder string) bool {
	if _, ok := s.entries[holder]; !ok {
		return false
	}
	delete(s.entries, holder)
	s.order = slices.DeleteFunc(s.order, func(h string) bool { return h == holder })
	return true
}

// union returns every holder's servers and search domains, deduplicated,
// in holder order.
func (s *dnsHolderSet) union() (servers, search []string) {
	for _, h := range s.order {
		sv, sd := splitDNSEntries(s.entries[h])
		for _, v := range sv {
			if !slices.Contains(servers, v) {
				servers = append(servers, v)
			}
		}
		for _, v := range sd {
			if !slices.Contains(search, v) {
				search = append(search, v)
			}
		}
	}
	return servers, search
}

// SetDNS registers holder's DNS entries (servers and search domains, as in
// wg-quick's `DNS = 1.1.1.1, corp.example`) and applies the union of all
// holders to every network service. Calling it again for the same holder
// replaces its entries.
func (m *DarwinManager) SetDNS(holder string, entries []string) error {
	if len(entries) == 0 {
		return nil
	}
	services := getAllNetworkServices()
	if len(services) == 0 {
		return fmt.Errorf("no network services found")
	}

	dnsMu.Lock()
	prev, hadPrev := dnsHolders.get(holder)
	dnsHolders.set(holder, entries)
	applyDNSUnionLocked(services)
	servers, _ := dnsHolders.union()
	var verifyErr error
	if len(servers) > 0 {
		verifyErr = verifyDNS(services, servers[0])
	}
	if verifyErr != nil {
		if hadPrev {
			dnsHolders.set(holder, prev)
		} else {
			dnsHolders.remove(holder)
		}
		releaseOrReapplyLocked(services)
	}
	dnsMu.Unlock()

	if verifyErr != nil {
		return fmt.Errorf("DNS applied but verification failed: %w", verifyErr)
	}
	// Even split tunnels need the route monitor once DNS is overridden: a
	// network switch can make macOS rewrite the service's DNS.
	m.startMonitor()
	return nil
}

// RestoreDNS releases holder. The remaining holders' union is re-applied,
// or the original settings are restored if none remain.
func (m *DarwinManager) RestoreDNS(holder string) error {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	if !dnsHolders.remove(holder) {
		return nil
	}
	releaseOrReapplyLocked(getAllNetworkServices())
	return nil
}

// releaseOrReapplyLocked applies the current union, or restores the
// baseline and drops the journal when no holder is left.
func releaseOrReapplyLocked(services []string) {
	if dnsHolders.len() > 0 {
		applyDNSUnionLocked(services)
		return
	}
	saved, search := dnsSavedDNS, dnsSavedSearch
	dnsSavedDNS = make(map[string][]string)
	dnsSavedSearch = make(map[string][]string)
	restoreBaselineFn(saved, search)
	// Drop the journal only after the restore ran, so a crash mid-restore
	// still leaves it for the next startup.
	removeDNSJournalLocked()
}

// applyDNSUnionLocked captures the baseline of any service not yet saved
// (journaling it before it is overridden), then sets every service to the
// holders' union. A field the union leaves empty falls back to that
// service's baseline, so a departed tunnel's entries never linger.
func applyDNSUnionLocked(services []string) {
	captureBaselineLocked(services)
	servers, search := dnsHolders.union()
	var wg sync.WaitGroup
	for _, svc := range services {
		sv, sd := servers, search
		if len(sv) == 0 {
			sv = dnsSavedDNS[svc]
		}
		if len(sd) == 0 {
			sd = dnsSavedSearch[svc]
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			setServiceDNS(svc, "-setdnsservers", sv)
			setServiceDNS(svc, "-setsearchdomains", sd)
		}()
	}
	wg.Wait()
	flushDNSCache()
}

// captureBaselineLocked saves the current DNS of every service not yet in
// the baseline and journals it. Services that appear mid-session (a new
// USB adapter) get captured the first time they are seen.
func captureBaselineLocked(services []string) {
	var missing []string
	for _, svc := range services {
		if _, ok := dnsSavedDNS[svc]; !ok {
			missing = append(missing, svc)
		}
	}
	if len(missing) == 0 {
		return
	}
	dns := make([][]string, len(missing))
	search := make([][]string, len(missing))
	var wg sync.WaitGroup
	for i, svc := range missing {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dns[i], _ = getCurrentDNS(svc)
			search[i], _ = getCurrentSearchDomains(svc)
		}()
	}
	wg.Wait()
	for i, svc := range missing {
		dnsSavedDNS[svc] = dns[i]
		dnsSavedSearch[svc] = search[i]
	}
	writeDNSJournalLocked()
}

// reapplyDNSIfDrifted re-pushes the union only if some service no longer
// has it (macOS rewrites DNS on network switches) or a new service
// appeared. Route-event bursts are frequent; skipping the no-op case avoids
// a networksetup fan-out and an mDNSResponder HUP on each of them.
func reapplyDNSIfDrifted() {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	if dnsHolders.len() == 0 {
		return
	}
	want, _ := dnsHolders.union()
	services := getAllNetworkServices()
	drifted := make([]bool, len(services))
	var wg sync.WaitGroup
	for i, svc := range services {
		if _, ok := dnsSavedDNS[svc]; !ok {
			drifted[i] = true
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := getCurrentDNS(svc)
			drifted[i] = err != nil || (len(want) > 0 && !slices.Equal(got, want))
		}()
	}
	wg.Wait()
	if slices.Contains(drifted, true) {
		slog.Info("DNS drifted from the tunnels' settings, re-applying")
		applyDNSUnionLocked(services)
	}
}

// setServiceDNS runs `networksetup <flag> svc values...`, or "Empty" to
// clear the field.
func setServiceDNS(svc, flag string, values []string) {
	args := []string{flag, svc}
	if len(values) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, values...)
	}
	if err := run(cmdNetworksetup, args...); err != nil {
		slog.Warn("networksetup failed", "service", svc, "flag", flag, "error", err)
	}
}

// restoreDNSBaseline pushes saved settings back to every service.
func restoreDNSBaseline(savedDNS, savedSearch map[string][]string) {
	var wg sync.WaitGroup
	for svc, orig := range savedDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			setServiceDNS(svc, "-setdnsservers", orig)
		}()
	}
	for svc, orig := range savedSearch {
		wg.Add(1)
		go func() {
			defer wg.Done()
			setServiceDNS(svc, "-setsearchdomains", orig)
		}()
	}
	wg.Wait()
	flushDNSCache()
}

// verifyDNS checks that at least one service reports the expected primary
// server, retrying once: MDM profiles or permission issues can make
// networksetup silently ignore the change.
func verifyDNS(services []string, expected string) error {
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		found := make([]bool, len(services))
		var wg sync.WaitGroup
		for i, svc := range services {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cur, _ := getCurrentDNS(svc)
				found[i] = slices.Contains(cur, expected)
			}()
		}
		wg.Wait()
		if slices.Contains(found, true) {
			return nil
		}
	}
	return fmt.Errorf("DNS server %s not found on any network service after apply", expected)
}

// flushDNSCache makes lookups use the new servers immediately (as wg-quick
// does at the end of set_dns). Best-effort.
func flushDNSCache() {
	_ = run(cmdDscacheutil, "-flushcache")
	_ = run(cmdKillall, "-HUP", "mDNSResponder")
}

// splitDNSEntries partitions a mixed DNS list into IP servers and search
// domains.
func splitDNSEntries(entries []string) (servers, search []string) {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if net.ParseIP(e) != nil {
			servers = append(servers, e)
		} else {
			search = append(search, e)
		}
	}
	return
}
