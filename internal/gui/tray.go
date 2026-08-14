package gui

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wgapp "github.com/steiale/wireguide/internal/app"
	"github.com/steiale/wireguide/internal/domain"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/icons"
)

//go:embed assets/lockplus_green.png
var trayLockGreenPNG []byte

//go:embed assets/lockplus_orange.png
var trayLockOrangePNG []byte

//go:embed assets/lockplus_off.png
var trayLockOffPNG []byte

// Tray icon variants — always SetIcon (non-template) to avoid a Wails v3 bug
// where SetTemplateIcon makes all future SetIcon calls render monochrome.
//
//   - trayGreenIcon  — padlock, + is green  (connected, handshake confirmed)
//   - trayAmberIcon  — padlock, + is orange (connected, no handshake yet)
//   - trayOffIcon    — padlock, + is gray   (disconnected)
var (
	trayGreenIcon []byte
	trayAmberIcon []byte
	trayOffIcon   []byte
)

func init() {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("tray icon init panicked, using fallback", "panic", r)
			trayGreenIcon = icons.SystrayMacTemplate
			trayAmberIcon = icons.SystrayMacTemplate
			trayOffIcon = icons.SystrayMacTemplate
		}
	}()
	trayGreenIcon = pngWith144DPI(trayLockGreenPNG)
	trayAmberIcon = pngWith144DPI(trayLockOrangePNG)
	trayOffIcon = pngWith144DPI(trayLockOffPNG)
}

// pngWith144DPI splices a pHYs chunk (144 DPI = 5669 pixels/metre) into a PNG
// immediately after its IHDR chunk. NSImage uses this metadata to determine
// the image's point size, enabling correct @2x Retina rendering without any
// explicit setSize call.
func pngWith144DPI(data []byte) []byte {
	const ppm = 5669    // pixels per metre ≈ 144 DPI
	const insertAt = 33 // byte offset right after PNG sig (8) + IHDR (25)
	if len(data) < insertAt {
		return data
	}
	chunk := make([]byte, 21)                // 4 len + 4 type + 4 x + 4 y + 1 unit + 4 crc
	binary.BigEndian.PutUint32(chunk[0:], 9) // data length
	copy(chunk[4:], "pHYs")
	binary.BigEndian.PutUint32(chunk[8:], ppm)
	binary.BigEndian.PutUint32(chunk[12:], ppm)
	chunk[16] = 1 // unit: metre
	h := crc32.NewIEEE()
	h.Write(chunk[4:17])
	binary.BigEndian.PutUint32(chunk[17:], h.Sum32())

	out := make([]byte, 0, len(data)+len(chunk))
	out = append(out, data[:insertAt]...)
	out = append(out, chunk...)
	out = append(out, data[insertAt:]...)
	return out
}

// formatSpeedFixed renders bytes/sec as exactly 4 chars + "K", padded with
// U+2007 FIGURE SPACE (digit-width in SF Pro) so the string always renders
// at the same pixel width regardless of value. Cap at 9999 K.
// Speeds between 0 and 1 KB/s render as "  <1K" so the tray label visibly
// distinguishes "traffic flowing but slow" from "no traffic at all".
func formatSpeedFixed(bps float64) string {
	const fig = " " // figure space = digit width
	if bps < 0 {
		bps = 0
	}
	if bps > 0 && bps < 1024 {
		return fig + fig + "<1K" // 2 fig spaces + "<1K" = same visual width as "   1K"
	}
	n := int(bps / 1024)
	if n > 9999 {
		n = 9999
	}
	s := fmt.Sprintf("%d", n)
	for len([]rune(s)) < 4 {
		s = fig + s
	}
	return s + "K"
}

// trayManager owns the system tray menu and its visual state.
//
// Two update paths:
//  1. updateStatus(status) — cheap, ≈1 Hz. Swaps icon + label, recomputes speeds. No IPC/disk.
//  2. rebuildMenu() — expensive, only on connect/disconnect/handshake transitions.
type trayManager struct {
	app        *application.App
	win        *application.WebviewWindow
	tray       *application.SystemTray
	svc        *wgapp.TunnelService
	doShutdown func()

	mu            sync.Mutex
	activeTunnels map[string]bool
	hasHandshake  map[string]bool
	tunnelStatus  map[string]domain.ConnectionStatus
	rebuildTimer  *time.Timer
	rebuilding    atomic.Bool
	// rebuildPending is set when a rebuild request arrives while another is
	// already in flight (the CAS in rebuildMenu fails). Without this, that
	// request was silently dropped — a disconnect transition landing while
	// a slower prior rebuild (disk reads for tunnels + settings, can exceed
	// the 100ms scheduleRebuild delay) is still running left the tray menu
	// stale until some LATER, unrelated state-change event happened to
	// trigger another rebuild. The in-flight rebuild checks this flag right
	// before releasing `rebuilding` and re-schedules itself if set.
	rebuildPending  atomic.Bool
	lastMenuRebuild time.Time

	prevRx        map[string]int64
	prevTx        map[string]int64
	prevStatTime  time.Time
	speedRx       float64
	speedTx       float64
	tunnelSpeedRx map[string]float64
	tunnelSpeedTx map[string]float64
}

func newTrayManager(app *application.App, win *application.WebviewWindow, tray *application.SystemTray, svc *wgapp.TunnelService, doShutdown func()) *trayManager {
	return &trayManager{
		app:           app,
		win:           win,
		tray:          tray,
		svc:           svc,
		doShutdown:    doShutdown,
		tunnelStatus:  make(map[string]domain.ConnectionStatus),
		prevRx:        make(map[string]int64),
		prevTx:        make(map[string]int64),
		tunnelSpeedRx: make(map[string]float64),
		tunnelSpeedTx: make(map[string]float64),
	}
}

func (t *trayManager) initialBuild() {
	t.rebuildMenu()
	// No OnClick: Wails' event monitor sets statusItem.menu before the click
	// is processed, so macOS shows the menu via native tracking. The synthetic
	// mouseDown path (OpenMenu) breaks on macOS 27+.
	// Duration in menu items stays fresh via the 30s periodic rebuild below.
}

// updateStatus is called for every status event (≈1 Hz).
// Swaps icon, updates two-line speed label via SetLabel, no IPC or disk I/O.
func (t *trayManager) updateStatus(status domain.ConnectionStatus) {
	newActive := make(map[string]bool, len(status.ActiveTunnels))
	for _, n := range status.ActiveTunnels {
		newActive[n] = true
	}

	newHS := make(map[string]bool)
	newCache := make(map[string]domain.ConnectionStatus)
	for _, ts := range status.Tunnels {
		newHS[ts.TunnelName] = ts.HasHandshake
		newCache[ts.TunnelName] = ts
	}
	// Always overwrite with the primary status so full fields (Duration, rx/tx)
	// take precedence over the lightweight per-tunnel entries in status.Tunnels.
	if status.TunnelName != "" {
		newHS[status.TunnelName] = status.HasHandshake
		newCache[status.TunnelName] = status
	}

	now := time.Now()

	t.mu.Lock()
	prevActive := t.activeTunnels
	prevHS := t.hasHandshake
	t.activeTunnels = newActive
	t.hasHandshake = newHS
	t.tunnelStatus = newCache

	var dt float64
	if !t.prevStatTime.IsZero() {
		dt = now.Sub(t.prevStatTime).Seconds()
	}
	canCompute := dt >= 0.5

	newTunSpeedRx := make(map[string]float64, len(newActive))
	newTunSpeedTx := make(map[string]float64, len(newActive))
	newPrevRx := make(map[string]int64, len(newActive))
	newPrevTx := make(map[string]int64, len(newActive))
	var aggRx, aggTx float64

	for name := range newActive {
		ts, ok := newCache[name]
		if !ok {
			continue
		}
		newPrevRx[name] = ts.RxBytes
		newPrevTx[name] = ts.TxBytes
		if canCompute {
			if pRx, hadRx := t.prevRx[name]; hadRx {
				dRx := float64(ts.RxBytes - pRx)
				if dRx < 0 {
					dRx = 0
				}
				rate := dRx / dt
				newTunSpeedRx[name] = rate
				aggRx += rate
			}
			if pTx, hadTx := t.prevTx[name]; hadTx {
				dTx := float64(ts.TxBytes - pTx)
				if dTx < 0 {
					dTx = 0
				}
				rate := dTx / dt
				newTunSpeedTx[name] = rate
				aggTx += rate
			}
		}
	}

	// The byte-count baseline (prevRx/prevTx) MUST advance in lockstep with
	// the time baseline (prevStatTime) — both only on ticks where canCompute
	// is true. OpenVPN's management interface pushes a status update on every
	// >BYTECOUNT: notification via a dedicated broadcast path (see
	// helper.broadcastOvpnStatus), which arrives far more often than the
	// ~1 Hz cadence this rate calc assumes. Committing prevRx/prevTx on every
	// call (including the sub-0.5s bursts that fail canCompute) desynced the
	// two baselines: dt kept measuring a real ~1s gap while the byte baseline
	// had just been refreshed milliseconds earlier, so the computed delta was
	// almost always ~0 regardless of actual throughput.
	if canCompute {
		t.speedRx = aggRx
		t.speedTx = aggTx
		t.tunnelSpeedRx = newTunSpeedRx
		t.tunnelSpeedTx = newTunSpeedTx
		t.prevStatTime = now
		t.prevRx = newPrevRx
		t.prevTx = newPrevTx
	} else if t.prevStatTime.IsZero() {
		t.prevStatTime = now
	}

	speedRx := t.speedRx
	speedTx := t.speedTx
	t.mu.Unlock()

	anyConnected := len(newActive) > 0
	anyHandshake := false
	for name := range newActive {
		if newHS[name] {
			anyHandshake = true
			break
		}
	}

	switch {
	case anyConnected && anyHandshake:
		t.tray.SetIcon(trayGreenIcon)
		t.tray.SetTooltip("LockPlus — " + strings.Join(status.ActiveTunnels, ", "))
	case anyConnected:
		t.tray.SetIcon(trayAmberIcon)
		t.tray.SetTooltip("LockPlus — connecting…")
	default:
		if runtime.GOOS == "darwin" {
			t.tray.SetIcon(trayOffIcon)
		}
		t.tray.SetTooltip("LockPlus")
	}

	if runtime.GOOS == "darwin" {
		var label string
		if anyConnected {
			label = "↓" + formatSpeedFixed(speedRx) + " ↑" + formatSpeedFixed(speedTx)
		}
		application.InvokeAsync(func() { t.tray.SetLabel(label) })
	} else {
		if anyConnected {
			t.tray.SetLabel("LockPlus ●")
		} else {
			t.tray.SetLabel("LockPlus")
		}
	}

	changed := len(prevActive) != len(newActive)
	if !changed {
		for k := range prevActive {
			if !newActive[k] {
				changed = true
				break
			}
		}
	}
	if !changed {
		for name := range newActive {
			if newHS[name] != prevHS[name] {
				changed = true
				break
			}
		}
	}
	if changed {
		t.scheduleRebuild()
	} else if anyConnected {
		t.mu.Lock()
		periodicDue := now.Sub(t.lastMenuRebuild) >= 30*time.Second
		if periodicDue {
			t.lastMenuRebuild = now
		}
		t.mu.Unlock()
		if periodicDue {
			t.scheduleRebuild()
		}
	}
}

func (t *trayManager) scheduleRebuild() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rebuildTimer != nil {
		t.rebuildTimer.Stop()
	}
	t.rebuildTimer = time.AfterFunc(100*time.Millisecond, t.rebuildMenu)
}

func (t *trayManager) rebuildMenu() {
	if !t.rebuilding.CompareAndSwap(false, true) {
		// A rebuild is already in flight — don't drop this request, just
		// mark it so the in-flight one re-triggers a fresh rebuild for us
		// once it finishes (state may have changed again in the meantime).
		t.rebuildPending.Store(true)
		return
	}
	defer func() {
		t.rebuilding.Store(false)
		if t.rebuildPending.CompareAndSwap(true, false) {
			t.scheduleRebuild()
		}
	}()

	tunnels, err := t.svc.ListTunnelsLocal()
	if err != nil {
		slog.Debug("tray: list tunnels failed", "error", err)
	}

	settings, _ := t.svc.GetSettings()

	t.mu.Lock()
	activeSet := t.activeTunnels
	hsMap := t.hasHandshake
	statusCache := t.tunnelStatus
	t.mu.Unlock()

	m := t.app.NewMenu()
	m.Add("LockPlus").SetEnabled(false)
	m.AddSeparator()

	var connected, disconnected []wgapp.TunnelInfo
	for _, tun := range tunnels {
		if activeSet[tun.Name] {
			connected = append(connected, tun)
		} else {
			disconnected = append(disconnected, tun)
		}
	}

	addTunnelItem := func(tun wgapp.TunnelInfo) {
		isConnected := activeSet[tun.Name]
		glyph := "○"
		if isConnected && hsMap[tun.Name] {
			glyph = "●"
		} else if isConnected {
			glyph = "◐"
		}
		label := glyph + " " + tun.Name
		if isConnected {
			ts, hasStatus := statusCache[tun.Name]
			if hasStatus && ts.Duration != "" {
				label += "   " + ts.Duration
			}
		}
		tunName := tun.Name
		m.Add(label).OnClick(func(_ *application.Context) {
			t.mu.Lock()
			active := t.activeTunnels[tunName]
			t.mu.Unlock()
			if active {
				if err := t.svc.DisconnectTunnel(tunName); err != nil {
					slog.Warn("tray disconnect failed", "tunnel", tunName, "error", err)
				}
			} else {
				if err := t.svc.Connect(tunName); err != nil {
					slog.Warn("tray connect failed", "tunnel", tunName, "error", err)
				}
			}
		})
	}

	for _, tun := range connected {
		addTunnelItem(tun)
	}
	if len(connected) > 0 && len(disconnected) > 0 {
		m.AddSeparator()
	}
	for _, tun := range disconnected {
		addTunnelItem(tun)
	}

	m.AddSeparator()

	if settings != nil {
		ks := settings.KillSwitch
		ksLabel := "  Kill Switch"
		if ks {
			ksLabel = "✓ Kill Switch"
		}
		m.Add(ksLabel).OnClick(func(_ *application.Context) {
			s, _ := t.svc.GetSettings()
			if s == nil {
				return
			}
			s.KillSwitch = !s.KillSwitch
			_ = t.svc.SaveSettings(s)
			_ = t.svc.SetKillSwitch(s.KillSwitch)
			t.scheduleRebuild()
		})
	}

	m.AddSeparator()
	m.Add("Show Window").OnClick(func(_ *application.Context) {
		showDock()
	})
	m.AddSeparator()
	m.Add("Quit").OnClick(func(_ *application.Context) {
		// doShutdown is sync.Once-guarded, safe to call here even though
		// app.Quit() below also triggers it via
		// ApplicationWillTerminate (gui.go) — calling it here too just
		// starts shutdown promptly rather than waiting on that event.
		// tray.Destroy() is NOT also called here, though: unlike
		// doShutdown, the underlying native destroy is not guaranteed
		// idempotent, and ApplicationWillTerminate's handler already
		// destroys the same tray once app.Quit() below fires it — calling
		// Destroy() from both places double-destroyed the same NSStatusItem.
		t.doShutdown()
		t.app.Quit()
	})
	t.tray.SetMenu(m)
}
