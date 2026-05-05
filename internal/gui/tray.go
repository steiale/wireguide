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

// Tray icon variants — always SetIcon (non-template) to avoid a Wails v3 bug
// where SetTemplateIcon makes all future SetIcon calls render monochrome.
//
//   - trayGreenIcon  — + is green  (connected, handshake confirmed)
//   - trayAmberIcon  — + is amber  (connected, no handshake yet)
//   - trayOffIcon    — + is dim    (disconnected)
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
	trayGreenIcon = buildWPlusIcon(color.NRGBA{52, 199, 89, 255})   // macOS systemGreen
	trayAmberIcon = buildWPlusIcon(color.NRGBA{255, 159, 10, 255})  // macOS systemOrange
	trayOffIcon = buildWPlusIcon(color.NRGBA{255, 255, 255, 110})   // dim white
}

// trayCanvasH is 44 px — the exact @2x height of the macOS menu bar (22 pt × 2).
// Using this precise value avoids the non-integer downscale macOS would apply
// to a taller canvas, which caused the + bars to render with different effective
// widths (vertical thinner than horizontal) due to rounding.
const trayCanvasH = 44

// buildWPlusIcon renders the W+ menu bar icon as a non-template PNG.
// Canvas is exactly 44 px tall for pixel-perfect @2x Retina rendering.
// The W glyph is tinted white; the + is drawn in plusColor as the status indicator.
func buildWPlusIcon(plusColor color.NRGBA) []byte {
	base, err := png.Decode(bytes.NewReader(icons.SystrayMacTemplate))
	if err != nil {
		slog.Warn("failed to decode base tray icon", "error", err)
		return icons.SystrayMacTemplate
	}

	trimmed := trimAndSquare(base)
	wSide := trimmed.Bounds().Dx()
	if wSide == 0 {
		return icons.SystrayMacTemplate
	}

	// Re-tint W to white, preserving alpha.
	for y := 0; y < wSide; y++ {
		for x := 0; x < wSide; x++ {
			_, _, _, a := trimmed.At(x, y).RGBA()
			if a > 0 {
				trimmed.SetNRGBA(x, y, color.NRGBA{255, 255, 255, uint8(a >> 8)})
			}
		}
	}

	// Layout (all in @2x pixels, canvas exactly 44 px tall):
	//
	//   ┌────────────┬─────┬────────────┐
	//   │     W      │ gap │     +      │
	//   │  (49 × 33) │  4  │  (44 × 44) │
	//   └────────────┴─────┴────────────┘
	//
	// The + lives in a square 44×44 sub-region so both bars scale uniformly.
	const (
		gap     = 0
		plusW   = 24          // tight section: armLen*2+barHalf*2 = 28, minus dead space
		barHalf = 3           // 7-px-thick bars
		armLen  = 11          // arms extend 11 px each side of centre (22 px cross)
	)
	wDstH := trayCanvasH * 75 / 100    // 33 — breathing room top/bottom
	wDstW := wDstH * 150 / 100         // 49 — 1.5× wider than tall
	wOffY := (trayCanvasH - wDstH) / 2 // 5 — centre W vertically
	canvasW := wDstW + gap + plusW
	canvasH := trayCanvasH
	plusCX := wDstW + gap + plusW/2
	plusCY := trayCanvasH / 2

	dst := image.NewNRGBA(image.Rect(0, 0, canvasW, canvasH))

	// W: nearest-neighbour scale from wSide×wSide into wDstW×wDstH, centred.
	for y := 0; y < wDstH; y++ {
		for x := 0; x < wDstW; x++ {
			srcX := x * wSide / wDstW
			srcY := y * wSide / wDstH
			dst.SetNRGBA(x, y+wOffY, trimmed.NRGBAAt(srcX, srcY))
		}
	}

	// Horizontal bar of +.
	for x := plusCX - armLen; x <= plusCX+armLen; x++ {
		for y := plusCY - barHalf; y <= plusCY+barHalf; y++ {
			if x >= 0 && x < canvasW && y >= 0 && y < canvasH {
				dst.SetNRGBA(x, y, plusColor)
			}
		}
	}
	// Vertical bar of +.
	for y := plusCY - armLen; y <= plusCY+armLen; y++ {
		for x := plusCX - barHalf; x <= plusCX+barHalf; x++ {
			if x >= 0 && x < canvasW && y >= 0 && y < canvasH {
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
// then centres in a square canvas (max of width/height).
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


// formatSpeed renders bytes/sec in compact form for tunnel menu items.
func formatSpeed(bps float64) string {
	if bps < 0 || bps < 1024 {
		return "0"
	}
	if bps >= 1024*1024 {
		return fmt.Sprintf("%.1fM", bps/(1024*1024))
	}
	return fmt.Sprintf("%dK", int(bps/1024))
}

// formatSpeedFixed renders bytes/sec as exactly 4 chars + "K", padded with
// U+2007 FIGURE SPACE (digit-width in SF Pro) so the string always renders
// at the same pixel width regardless of value. Cap at 9999 K.
func formatSpeedFixed(bps float64) string {
	const fig = " " // figure space = digit width
	if bps < 0 {
		bps = 0
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

	if canCompute {
		t.speedRx = aggRx
		t.speedTx = aggTx
		t.tunnelSpeedRx = newTunSpeedRx
		t.tunnelSpeedTx = newTunSpeedTx
		t.prevStatTime = now
	} else if t.prevStatTime.IsZero() {
		t.prevStatTime = now
	}
	t.prevRx = newPrevRx
	t.prevTx = newPrevTx

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
		var label string
		if anyConnected {
			label = "↓" + formatSpeedFixed(speedRx) + " ↑" + formatSpeedFixed(speedTx)
		}
		application.InvokeAsync(func() { t.tray.SetLabel(label) })
	} else {
		if anyConnected {
			t.tray.SetLabel("WireGuide+ ●")
		} else {
			t.tray.SetLabel("WireGuide+")
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
