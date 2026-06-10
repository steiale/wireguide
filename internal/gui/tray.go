package gui

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"hash/crc32"
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

//go:embed assets/wplus.png
var trayWPlusPNG []byte

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
	trayGreenIcon = buildWPlusIcon(color.NRGBA{52, 199, 89, 255})  // macOS systemGreen
	trayAmberIcon = buildWPlusIcon(color.NRGBA{255, 159, 10, 255}) // macOS systemOrange
	trayOffIcon = buildWPlusIcon(color.NRGBA{255, 255, 255, 140})  // dim white
}

// buildWPlusIcon tints the embedded @2x W+ glyph with tintColor and returns
// a PNG with an embedded pHYs chunk declaring 144 DPI. When NSImage(data:)
// loads this PNG it reads the resolution metadata and sets the display size to
// pixelWidth/2 × pixelHeight/2 points — so a 44×44 px PNG renders at 22×22 pt
// with full @2x Retina sharpness, no CGo fixup required.
func buildWPlusIcon(tintColor color.NRGBA) []byte {
	src, err := png.Decode(bytes.NewReader(trayWPlusPNG))
	if err != nil {
		slog.Warn("failed to decode wplus.png", "error", err)
		return icons.SystrayMacTemplate
	}

	sb := src.Bounds()
	dst := image.NewNRGBA(sb)
	for y := sb.Min.Y; y < sb.Max.Y; y++ {
		for x := sb.Min.X; x < sb.Max.X; x++ {
			_, _, _, a := src.At(x, y).RGBA()
			alpha := uint8(a >> 8)
			if alpha > 0 {
				dst.SetNRGBA(x, y, color.NRGBA{tintColor.R, tintColor.G, tintColor.B, alpha})
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		slog.Warn("failed to encode W+ tray icon", "error", err)
		return icons.SystrayMacTemplate
	}
	return pngWith144DPI(buf.Bytes())
}

// pngWith144DPI splices a pHYs chunk (144 DPI = 5669 pixels/metre) into a PNG
// immediately after its IHDR chunk. NSImage uses this metadata to determine
// the image's point size, enabling correct @2x Retina rendering without any
// explicit setSize call.
func pngWith144DPI(data []byte) []byte {
	const ppm = 5669     // pixels per metre ≈ 144 DPI
	const insertAt = 33  // byte offset right after PNG sig (8) + IHDR (25)
	if len(data) < insertAt {
		return data
	}
	chunk := make([]byte, 21) // 4 len + 4 type + 4 x + 4 y + 1 unit + 4 crc
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
		t.doShutdown()
		t.tray.Destroy()
		t.app.Quit()
	})
	t.tray.SetMenu(m)
}
