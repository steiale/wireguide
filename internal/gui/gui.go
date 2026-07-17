// Package gui contains the GUI-mode runtime for the LockPlus app.
//
// The package is split so each file has a single reason to change:
//   - gui.go              (this file)  — Run() entry, Wails app + window setup
//   - tray.go                           — system tray menu (event-driven rebuild)
//   - event_bridge.go                   — IPC event forwarding + subscription
//   - helper_lifecycle.go               — helper spawn, health check, auto-reconnect
package gui

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	wgapp "github.com/steiale/wireguide/internal/app"
	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/elevate"
	"github.com/steiale/wireguide/internal/history"
	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/storage"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

// ReconnectEvent mirrors ipc.ReconnectStateDTO for Wails event emission.
type ReconnectEvent struct {
	Reconnecting bool `json:"reconnecting"`
	Attempt      int  `json:"attempt"`
	MaxAttempts  int  `json:"max_attempts"`
}

// HelperEvent notifies the frontend about helper process health changes.
type HelperEvent struct {
	Alive   bool   `json:"alive"`
	Message string `json:"message"`
}

// Register Wails event payload types. Called once per process from init.
func init() {
	application.RegisterEvent[domain.ConnectionStatus]("status")
	application.RegisterEvent[ReconnectEvent]("reconnect")
	application.RegisterEvent[map[string]any]("files-dropped")
	application.RegisterEvent[HelperEvent]("helper")
	application.RegisterEvent[struct{}]("helper_reset")
	application.RegisterEvent[ipc.AuthPromptEventPayload]("auth_prompt")
}

// Run starts the GUI process. Blocks until the Wails app exits.
func Run(assetsHandler http.Handler, dataDir string) error {
	// 0. Install the slog handler that broadcasts to the LogViewer. Do this
	// first so every subsequent log call (path init, helper spawn, etc.) is
	// captured. The Wails app isn't built yet; bindAppToLogHandler wires
	// the app reference later once application.New returns.
	installGUILogHandler()
	// Expose the level mutator to the Wails-bound service layer so
	// Settings changes can reach us without an import cycle.
	wgapp.SetGUILogLevelSetter(setGUILogLevel)

	// 1. Local storage
	paths, err := storage.GetPaths()
	if err != nil {
		return fmt.Errorf("paths: %w", err)
	}
	if err := paths.EnsureDirs(); err != nil {
		return fmt.Errorf("create dirs: %w", err)
	}
	paths.MigrateLegacyTunnels()
	tunnelStore := storage.NewTunnelStore(paths.TunnelsDir)
	settingsStore := storage.NewSettingsStore(paths.ConfigDir)
	wifiRulesStore := storage.NewWifiRulesStore(paths.ConfigDir)
	historyStore := history.NewStore(paths.ConfigDir)
	// Close any sessions left open from a previous crash (the GUI didn't get
	// a chance to write EndTime). Marks them as "app_quit" so they aren't
	// shown as still-active in the history view.
	historyStore.CloseOpenSessions("app_quit")

	// Apply persisted log level to the GUI side immediately (helper-side
	// gets it after ensureHelper + the SaveSettings path).
	if s, err := settingsStore.Load(); err == nil && s != nil && s.LogLevel != "" {
		setGUILogLevel(s.LogLevel)
	}

	// 2. Helper process — bootstrapped asynchronously after the Wails event
	// loop is running (see the ApplicationStarted hook below).
	//
	// Why async: ensureHelper() can block for many seconds — it spawns
	// `osascript` for the admin password prompt and then polls for the helper
	// socket. On macOS, AppKit's run loop must own the main thread before any
	// window can be shown. If we run ensureHelper() synchronously here, the
	// admin prompt holds up app.Run(), and the main window never appears
	// until after the helper finishes installing. In the worst case (the
	// recurring "ghost process" bug) AppKit's startup races the osascript
	// launch and the window never shows at all, even after the helper is up.
	//
	// The holder starts empty. Every IPC call site already returns
	// errHelperUnavailable when the holder is nil, and the event bridge /
	// health monitor / wifi lifecycle all tolerate a nil client. Once the
	// background bootstrap succeeds it calls clients.Set(c) and triggers a
	// resubscribe — the frontend reacts to the resulting "helper_reset"
	// event by re-fetching tunnel state.
	clients := ipc.NewClientHolder(nil)

	// 3. Wails service
	tunnelService := wgapp.NewTunnelService(tunnelStore, settingsStore, wifiRulesStore, historyStore, clients)

	// 4. Wails app
	app := application.New(application.Options{
		Name:        "LockPlus",
		Description: "Cross-platform WireGuard desktop client",
		Services: []application.Service{
			application.NewService(tunnelService),
		},
		Assets: application.AssetOptions{
			Handler: assetsHandler,
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})
	tunnelService.SetApp(app)
	bindAppToLogHandler(app)

	// Register the log event shape so Wails knows how to marshal it.
	application.RegisterEvent[ipc.LogEntry]("log")

	// 5. Main window
	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:          "LockPlus",
		Width:          680,
		Height:         770,
		EnableFileDrop: true,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(0, 20, 41), // matches --bg-primary dark (#001429)
		URL:              "/",
	})

	// macOS standard: close button hides the window instead of destroying it.
	// The app stays alive in the tray; "Show Window" brings it back.
	//
	// CRITICAL: Must use RegisterHook, NOT OnWindowEvent. Wails registers
	// its own OnWindowEvent(WindowClosing) listener that calls markAsDestroyed
	// + close. Listeners run in separate goroutines, so Cancel() from our
	// listener races with Wails' listener — the window gets destroyed despite
	// Cancel. Hooks run sequentially BEFORE listeners, so Cancel() here
	// reliably prevents Wails' default close/destroy behavior.
	win.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		event.Cancel()
		win.Hide()
		hideDock()
	})

	// Wire the window into the service (for ResizeToFit) and tray helpers.
	tunnelService.SetWindow(win)
	dockWindow = win

	// Native file drop forwarded to frontend
	win.OnWindowEvent(events.Common.WindowFilesDropped, func(event *application.WindowEvent) {
		files := event.Context().DroppedFiles()
		app.Event.Emit("files-dropped", map[string]any{"files": files})
	})

	// 6. System tray — always use SetIcon (never SetTemplateIcon) to avoid
	// a Wails v3 bug where the isTemplateIcon sticky flag makes all
	// subsequent SetIcon calls render as monochrome template icons.
	tray := app.SystemTray.New()
	if runtime.GOOS == "darwin" {
		tray.SetIcon(trayOffIcon)
	} else {
		tray.SetLabel("LockPlus")
	}
	tray.SetTooltip("LockPlus")

	// 7. Shutdown coordination (declared upfront so closures can reference it)
	var (
		shutdownOnce sync.Once
		doShutdown   func()
	)
	doShutdown = func() {
		shutdownOnce.Do(func() {
			slog.Info("shutting down GUI + helper")
			// Close any open history sessions BEFORE the helper shuts down
			// so we can still query GetStatus for last-known rx/tx.
			tunnelService.CloseHistorySessions("app_quit")
			c := clients.Get()
			if c != nil {
				// Disconnect EVERY active tunnel, not just one. A single
				// nameless MethodDisconnect call only tears down the
				// helper's first active tunnel (WG first, else the first
				// OpenVPN tunnel) — with multiple concurrent tunnels
				// (WG+OVPN, or two WG tunnels), the others were left
				// running under the LaunchDaemon after quit, even though
				// CloseHistorySessions just marked ALL of their sessions
				// closed as "app_quit" a moment ago. tunnelService.callLong
				// already gives Disconnect its own generous timeout
				// (matching the 60s budget used everywhere else — DNS
				// restore + networksetup calls across services + route
				// teardown can take 15+ s on macOS).
				if names, err := tunnelService.ActiveTunnelNames(); err == nil {
					for _, name := range names {
						_ = tunnelService.DisconnectTunnel(name)
					}
				} else {
					// Fallback: helper unreachable via the normal call path
					// for some reason — still attempt the legacy single
					// nameless disconnect so we don't skip teardown entirely.
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					_ = c.CallWithContext(ctx, ipc.MethodDisconnect, nil, nil)
					cancel()
				}
				// Do NOT send MethodShutdown here. The helper installed as a
				// LaunchDaemon (KeepAlive=true) is owned by launchd — if we
				// tell it to shut down, launchd respawns it immediately, the
				// next GUI quit sends Shutdown again, and we land in a
				// helper-restart crash loop. MethodDisconnect above is enough
				// to tear down the VPN; launchd will keep the helper alive
				// for the next GUI launch (no admin prompt). In dev/osascript
				// mode the helper's own grace-window shutdown timer
				// (startShutdownTimer) handles teardown when the GUI's
				// control connection drops.
			}
			// Close in a goroutine with a short delay so the helper has
			// time to process the shutdown command without blocking the
			// macOS main thread (AppKit requires the main thread to stay
			// responsive during termination).
			go func() {
				time.Sleep(50 * time.Millisecond)
				clients.Close()
			}()
		})
	}

	trayMgr := newTrayManager(app, win, tray, tunnelService, doShutdown)
	trayMgr.initialBuild()

	if runtime.GOOS == "darwin" {
		app.Event.OnApplicationEvent(events.Mac.ApplicationWillTerminate, func(_ *application.ApplicationEvent) {
			doShutdown()
			tray.Destroy()
		})
	}

	// 8. IPC event bridge + helper health monitor.
	// The bridge owns the subscription and re-subscribes when the helper
	// process restarts. The health monitor swaps the client in the holder.
	// Pass the tray's cheap icon-update hook — NOT the full menu rebuild —
	// so the 1 Hz status stream doesn't trigger IPC round-trips on every event.
	//
	// The bridge tolerates a nil client (resubscribe is a no-op until the
	// holder has one), so we can construct it before the helper is ready.
	bridge := newEventBridge(app, clients, trayMgr.updateStatus, tunnelService.ReconcileHistoryFromStatus)
	bridge.start()

	healthDone := make(chan struct{})
	var healthWg sync.WaitGroup
	healthWg.Add(1)
	startHelperHealthMonitor(app, clients, dataDir, bridge, healthDone, &healthWg)

	// 8b. Wi-Fi auto-connect lifecycle. Its connect/disconnect paths go
	// through tunnelService, whose IPC calls already handle a not-yet-ready
	// helper by surfacing an error (logged, not fatal) — safe to start
	// before the helper bootstrap completes.
	wifiLC := startWifiLifecycle(tunnelService, wifiRulesStore)

	// 8c. Bootstrap the helper in the background once the Wails event loop
	// is running. ApplicationStarted fires on the main goroutine after the
	// app is ready to show windows, so the main window paints immediately
	// while the privileged helper installs in the background.
	//
	// sync.Once guards against ApplicationStarted firing multiple times
	// (e.g. activate/reopen on macOS) — we only want one bootstrap goroutine
	// no matter how many times the event fires.
	var bootstrapOnce sync.Once
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(_ *application.ApplicationEvent) {
		bootstrapOnce.Do(func() {
			go bootstrapHelper(app, clients, bridge, settingsStore, dataDir)
		})
	})

	// 9. Run (blocks)
	err = app.Run()
	wifiLC.stop()
	close(healthDone)
	healthWg.Wait()
	return err
}

// bootstrapHelper runs ensureHelper() in the background after the Wails app
// has started. On success it installs the client into the holder, kicks off
// the event subscription, pushes the persisted log level, and notifies the
// frontend. On terminal failure it shows an error dialog and quits the app.
//
// Splitting this from Run() lets app.Run() reach the AppKit main loop without
// being blocked by the privileged helper install (which can take several
// seconds and shows a modal admin password prompt on first launch).
func bootstrapHelper(app *application.App, clients *ipc.ClientHolder, bridge *eventBridge, settingsStore *storage.SettingsStore, dataDir string) {
	// Tell the frontend a connection is being established. The toast plumbing
	// in App.svelte shows this as "Connecting to helper..." instead of an
	// alarming "Helper process disconnected" message.
	app.Event.Emit("helper", HelperEvent{
		Alive:   false,
		Message: "Connecting to helper service...",
	})

	var newClient *ipc.Client
	for attempt := 0; attempt < 3; attempt++ {
		// Pass background context — ensureHelper manages its own internal
		// timeouts (2s for the initial ping, 60s fresh poll after SpawnHelper).
		// A deadline on the outer context races with SpawnHelper and cancels
		// the poll immediately when both expire at the same time.
		var err error
		newClient, err = ensureHelper(context.Background(), dataDir)
		if err == nil {
			break
		}
		slog.Warn("helper connection failed", "attempt", attempt+1, "error", err)

		// launchd refused to load the daemon (blocked Login Item / untrusted
		// signature). Retrying the same osascript install will keep failing —
		// the user must take an action in System Settings first. Show a
		// targeted dialog with a button that opens the right pane, then quit.
		// Looping here is the bug that produced the endless password prompts.
		var bootErr *elevate.BootstrapError
		if errors.As(err, &bootErr) {
			slog.Error("launchd blocked the helper daemon", "output", bootErr.Output)
			blockedCmd := `display dialog "macOS blocked LockPlus's background helper service.\n\nOpen System Settings → General → Login Items & Extensions, find LockPlus, and turn it ON. Then relaunch LockPlus.\n\nIf LockPlus is not listed, restart your Mac and try again." buttons {"Open Login Items", "Quit"} default button "Open Login Items" with title "LockPlus" with icon stop`
			out, _ := exec.Command("osascript", "-e", blockedCmd).Output()
			if strings.Contains(string(out), "Open Login Items") {
				// x-apple.systempreferences URL for the Login Items pane.
				_ = exec.Command("open", "x-apple.systempreferences:com.apple.LoginItems-Settings.extension").Run()
			}
			app.Quit()
			return
		}

		if attempt < 2 {
			retryCmd := `display dialog "LockPlus needs its helper service to manage VPN connections.\n\nPlease grant administrator access when prompted." buttons {"Quit", "Retry"} default button "Retry" with title "LockPlus" with icon caution`
			out, retryErr := exec.Command("osascript", "-e", retryCmd).Output()
			if retryErr != nil || strings.Contains(string(out), "Quit") {
				slog.Error("helper setup cancelled by user")
				app.Quit()
				return
			}
			continue
		}
		slog.Error("helper connection failed after 3 attempts", "error", err)
		failCmd := `display dialog "LockPlus could not start its helper service.\n\nPlease quit any other running copies of LockPlus and try again." buttons {"Quit"} default button "Quit" with title "LockPlus" with icon stop`
		_, _ = exec.Command("osascript", "-e", failCmd).Output()
		app.Quit()
		return
	}

	// Install the new client and re-subscribe the event bridge. Resubscribe
	// (capitalised) emits "helper_reset" so the frontend reloads tunnel state
	// from a fresh helper.
	clients.Set(newClient)
	bridge.Resubscribe()

	// Push the persisted log level to the helper now that the event
	// subscription is live — ensures DEBUG from Settings takes effect
	// on helper-side records immediately after app launch.
	if s, err := settingsStore.Load(); err == nil && s != nil && s.LogLevel != "" {
		_ = newClient.Call(ipc.MethodSetLogLevel, ipc.SetLogLevelRequest{Level: s.LogLevel}, nil)
	}

	// Notify the frontend that helper IPC is now available. App.svelte uses
	// this to dismiss the connecting toast.
	app.Event.Emit("helper", HelperEvent{Alive: true})
	slog.Info("helper bootstrap complete")
}
