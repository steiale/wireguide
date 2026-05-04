package gui

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
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

// Tray icon variants.
//
// We always use SetIcon (non-template) to avoid a Wails v3 bug where
// SetTemplateIcon sets isTemplateIcon=true on the macosSystemTray struct and
// the subsequent SetIcon never clears it — causing all future icons to render
// monochrome.
//
// The icon is "W+" where the W is white and the + acts as the status indicator:
//   - trayGreenIcon  — + is green  (connected, handshake confirmed)
//   - trayAmberIcon  — + is amber  (connected, no handshake yet)
//   - trayOffIcon    — + is dim    (disconnected)
var (
	trayGreenIcon []byte
	trayAmberIcon []byte
	trayOffIcon   []byte
)

func init() {
	// Defensive: if buildWPlusIcon panics on a corrupt embedded asset, fall
	// back to the raw template so the app still launches with a usable tray.
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("tray icon init panicked, using fallback", "panic", r)
			trayGreenIcon = icons.SystrayMacTemplate
			trayAmberIcon = icons.SystrayMacTemplate
			trayOffIcon = icons.SystrayMacTemplate
		}
	}()
	trayGreenIcon = buildWPlusIcon(color.NRGBA{52, 199, 89, 255})   // macOS systemGreen
	trayAmberIcon = buildWPlusIcon(color.NRGBA{255, 159, 10, 255})  // macOS systemOrange
	trayOffIcon = buildWPlusIcon(color.NRGBA{255, 255, 255, 110})   // dim white
}

// buildWPlusIcon renders the "W+" menu bar icon as a non-template 64×64 PNG.
// The W glyph (from Wails's built-in template) is tinted white and placed in
// the left portion; a "+" is drawn on the right with the given plusColor so
// it never gets auto-converted to monochrome by macOS.
func buildWPlusIcon(plusColor color.NRGBA) []byte {
	base, err := png.Decode(bytes.NewReader(icons.SystrayMacTemplate))
	if err != nil {
		slog.Warn("failed to decode base tray icon", "error", err)
		return icons.SystrayMacTemplate
	}

	trimmed := trimAndSquare(base)
	wSide := trimmed.Bounds().Dx()

	// Re-tint W to white, preserving alpha.
	for y := 0; y < wSide; y++ {
		for x := 0; x < wSide; x++ {
			_, _, _, a := trimmed.At(x, y).RGBA()
			if a > 0 {
				trimmed.SetNRGBA(x, y, color.NRGBA{255, 255, 255, uint8(a >> 8)})
			}
		}
	}

	const (
		iconSize = 64
		wDst     = 40 // W fits in a 40×40 square, centred vertically
		wOffY    = (iconSize - wDst) / 2
		// + drawn in x=[44..63] (20 px wide), centred at y=32
		plusCX  = 54 // centre x
		plusCY  = 32 // centre y
		armLen  = 7  // extends ±armLen from centre
		barHalf = 1  // half bar-thickness → 3 px total
	)

	dst := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))

	// Scale W (wSide×wSide) into the left 40×40 region.
	for dy := 0; dy < wDst; dy++ {
		for dx := 0; dx < wDst; dx++ {
			srcX := dx * wSide / wDst
			srcY := dy * wSide / wDst
			dst.SetNRGBA(dx, wOffY+dy, trimmed.NRGBAAt(srcX, srcY))
		}
	}

	// Horizontal bar of +.
	for x := plusCX - armLen; x <= plusCX+armLen; x++ {
		for y := plusCY - barHalf; y <= plusCY+barHalf; y++ {
			if x >= 0 && x < iconSize && y >= 0 && y < iconSize {
				dst.SetNRGBA(x, y, plusColor)
			}
		}
	}
	// Vertical bar of +.
	for y := plusCY - armLen; y <= plusCY+armLen; y++ {
		for x := plusCX - barHalf; x <= plusCX+barHalf; x++ {
			if x >= 0 && x < iconSize && y >= 0 && y < iconSize {
				dst.SetNRGBA(x, y, plusColor)
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		slog.Warn("failed to encode W+ tray icon", "error", err)
		return icons.SystrayMacTemplate
	}
	return buf.Bytes()
}

// trimAndSquare finds the bounding box of non-transparent pixels, crops,
// then centres in a square canvas (max of width/height). Wails forces the
// tray icon to a thickness×thickness square, so providing a square image
// avoids distortion and gives us control over the padding.
func trimAndSquare(src image.Image) *image.NRGBA {
	b := src.Bounds()
	minX, minY, maxX, maxY := b.Max.X, b.Max.Y, b.Min.X, b.Min.Y
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			_, _, _, a := src.At(x, y).RGBA()
			if a > 0 {
				if x < minX {
					minX = x
				}
				if y < minY {
					minY = y
				}
				if x > maxX {
					maxX = x
				}
				if y > maxY {
					maxY = y
				}
			}
		}
	}
	if maxX < minX {
		return image.NewNRGBA(image.Rect(0, 0, 1, 1))
	}
	cropW := maxX - minX + 1
	cropH := maxY - minY + 1
	side := cropW
	if cropH > side {
		side = cropH
	}
	out := image.NewNRGBA(image.Rect(0, 0, side, side))
	offX := (side - cropW) / 2
	offY := (side - cropH) / 2
	for y := 0; y < cropH; y++ {
		for x := 0; x < cropW; x++ {
			out.Set(x+offX, y+offY, src.At(x+minX, y+minY))
		}
	}
	return out
}

// formatSpeed renders a bytes-per-second rate in a compact form suitable for
// the menu bar: "2.1M", "512K", or "0" when the rate is negligible. Negative
// inputs (possible if cumulative byte counters reset across helper restarts)
// are clamped to zero so the UI never shows a "-" prefix.
func formatSpeed(bps float64) string {
	if bps < 0 || bps < 1024 {
		// Below 1 KB/s — not worth showing a number.
		return "0"
	}
	if bps >= 1024*1024 {
		return fmt.Sprintf("%.1fM", bps/(1024*1024))
	}
	return fmt.Sprintf("%dK", int(bps/1024))
}

// trayManager owns the system tray menu and its visual state.
//
// There are TWO update paths, intentionally separate:
//
//  1. updateStatus(status) — cheap, called from the status event stream every
//     second. Swaps the icon and tooltip, recomputes per-tunnel speeds. NO
//     IPC, NO disk I/O.
//
//  2. rebuildMenu() — expensive, reconstructs the full menu. Called only when
//     the active tunnel set or handshake state changes.
type trayManager struct {
	app        *application.App
	win        *application.WebviewWindow
	tray       *application.SystemTray
	svc        *wgapp.TunnelService
	doShutdown func()

	mu            sync.Mutex
	activeTunnels map[string]bool
	hasHandshake  map[string]bool
	tunnelStatus  map[string]domain.ConnectionStatus // duration, bytes per tunnel
	rebuildTimer  *time.Timer
	rebuilding    atomic.Bool

	// Bandwidth tracking (all guarded by mu).
	prevRx         map[string]int64   // last seen cumulative RX bytes per tunnel
	prevTx         map[string]int64   // last seen cumulative TX bytes per tunnel
	prevStatTime   time.Time          // wall-clock of last speed computation
	speedRx        float64            // aggregate RX bytes/sec across active tunnels
	speedTx        float64            // aggregate TX bytes/sec across active tunnels
	tunnelSpeedRx  map[string]float64 // per-tunnel RX bytes/sec
	tunnelSpeedTx  map[string]float64 // per-tunnel TX bytes/sec
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

// initialBuild draws the menu once at startup.
func (t *trayManager) initialBuild() {
	t.rebuildMenu()
}

// updateStatus is called for every status event from the helper (≈1 Hz).
// It swaps the tray icon and tooltip, and recomputes per-tunnel speeds —
// O(n) over active tunnels, no IPC, no disk I/O.
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
	// Single-tunnel path: Tunnels[] may be absent; TunnelName carries the data.
	if status.TunnelName != "" {
		newHS[status.TunnelName] = status.HasHandshake
		if _, ok := newCache[status.TunnelName]; !ok {
			newCache[status.TunnelName] = status
		}
	}

	now := time.Now()

	t.mu.Lock()
	prevActive := t.activeTunnels
	prevHS := t.hasHandshake
	t.activeTunnels = newActive
	t.hasHandshake = newHS
	t.tunnelStatus = newCache

	// Compute per-tunnel and aggregate speeds. Use wall-clock delta with a
	// 500 ms minimum so the first event after a long idle (or near-duplicate
	// events) doesn't divide by ~zero and produce nonsense.
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
					dRx = 0 // counter reset (helper restart, tunnel re-up)
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

	if canCompute {
		t.speedRx = aggRx
		t.speedTx = aggTx
		t.tunnelSpeedRx = newTunSpeedRx
		t.tunnelSpeedTx = newTunSpeedTx
		t.prevStatTime = now
	} else if t.prevStatTime.IsZero() {
		// First sample — seed the timestamp so the next event has a delta.
		t.prevStatTime = now
	}
	// Always advance the byte snapshot, even when we skip rate computation,
	// so the next-but-one sample uses a fresh baseline.
	t.prevRx = newPrevRx
	t.prevTx = newPrevTx

	speedLabel := ""
	if len(newActive) > 0 {
		speedLabel = "↓" + formatSpeed(t.speedRx) + " ↑" + formatSpeed(t.speedTx)
	}
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
		t.tray.SetTooltip("WireGuide+ — " + strings.Join(status.ActiveTunnels, ", "))
	case anyConnected:
		t.tray.SetIcon(trayAmberIcon)
		t.tray.SetTooltip("WireGuide+ — connecting…")
	default:
		if runtime.GOOS == "darwin" {
			t.tray.SetIcon(trayOffIcon)
		}
		t.tray.SetTooltip("WireGuide+")
	}

	if runtime.GOOS == "darwin" {
		// SetLabel renders text to the right of the icon in the menu bar.
		// Always set it (including the empty string when disconnected) so a
		// stale label from a prior connection is cleared.
		t.tray.SetLabel(speedLabel)
	} else {
		if anyConnected {
			t.tray.SetLabel("WireGuide+ ●")
		} else {
			t.tray.SetLabel("WireGuide+")
		}
	}

	// Rebuild menu if active set OR handshake state changed. Speed updates
	// alone do NOT trigger a rebuild — the menu stays static between
	// connect/disconnect/handshake transitions to avoid flicker (the user
	// sees the live numbers via the menu bar label instead).
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
	}
}

// scheduleRebuild debounces rebuildMenu calls — multiple triggers within 100 ms
// are coalesced into a single rebuild.
func (t *trayManager) scheduleRebuild() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rebuildTimer != nil {
		t.rebuildTimer.Stop()
	}
	t.rebuildTimer = time.AfterFunc(100*time.Millisecond, t.rebuildMenu)
}

// rebuildMenu reconstructs the full tray menu. Uses ListTunnelsLocal (disk,
// no IPC) plus the cached activeTunnels / tunnelStatus maps.
func (t *trayManager) rebuildMenu() {
	if !t.rebuilding.CompareAndSwap(false, true) {
		return
	}
	defer t.rebuilding.Store(false)

	tunnels, err := t.svc.ListTunnelsLocal()
	if err != nil {
		slog.Debug("tray: list tunnels failed", "error", err)
	}

	settings, _ := t.svc.GetSettings()

	t.mu.Lock()
	activeSet := t.activeTunnels
	hsMap := t.hasHandshake
	statusCache := t.tunnelStatus
	tunSpeedRx := t.tunnelSpeedRx
	t.mu.Unlock()

	m := t.app.NewMenu()
	m.Add("WireGuide+").SetEnabled(false)
	m.AddSeparator()

	// Connected tunnels first, then disconnected.
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
			// Speed first, then duration: "↓2.1M · 1h 23m". Skip the speed
			// segment if we don't have a sample yet (first second of a
			// freshly connected tunnel).
			ts, hasStatus := statusCache[tun.Name]
			rate, hasRate := tunSpeedRx[tun.Name]
			parts := make([]string, 0, 2)
			if hasRate {
				parts = append(parts, "↓"+formatSpeed(rate))
			}
			if hasStatus && ts.Duration != "" {
				parts = append(parts, ts.Duration)
			}
			if len(parts) > 0 {
				label += "   " + strings.Join(parts, " · ")
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

	// Kill switch toggle — local settings read, no IPC needed to render the label.
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
		t.doShutdown()
		t.tray.Destroy()
		t.app.Quit()
	})
	t.tray.SetMenu(m)
}
