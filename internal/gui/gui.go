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
	"strings"
	"sync"

	wgapp "github.com/steiale/wireguide/internal/app"
	"github.com/steiale/wireguide/internal/domain"
	"github.com/steiale/wireguide/internal/elevate"
	"github.com/steiale/wireguide/internal/history"
	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/storage"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

// HelperEvent notifies the frontend about helper process health changes.
// GaveUp marks a terminal state: automatic recovery stopped and Message tells
// the user what to do, so the UI stops showing a "starting" spinner.
type HelperEvent struct {
	Alive   bool   `json:"alive"`
	Message string `json:"message"`
	GaveUp  bool   `json:"gave_up,omitempty"`
}

// TrayErrorEvent reports a tray-initiated connect/disconnect failure to the
// frontend, which shows it as a toast (the window is brought forward first).
type TrayErrorEvent struct {
	Action string `json:"action"` // "connect" | "disconnect"
	Tunnel string `json:"tunnel"`
	Error  string `json:"error"`
}

// Register Wails event payload types. Called once per process from init.
func init() {
	application.RegisterEvent[domain.ConnectionStatus]("status")
	application.RegisterEvent[map[string]any]("files-dropped")
	application.RegisterEvent[HelperEvent]("helper")
	application.RegisterEvent[struct{}]("helper_reset")
	application.RegisterEvent[ipc.AuthPromptEventPayload]("auth_prompt")
	application.RegisterEvent[TrayErrorEvent]("tray_error")
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

	// 4. Shutdown. Registered as Options.OnShutdown, which Wails runs
	// synchronously inside its cleanup (applicationShouldTerminate on macOS)
	// for every quit path — tray Quit, Cmd+Q, Dock, logout. An
	// ApplicationWillTerminate listener is NOT enough: listeners run async
	// after cleanup, so the process exits before tunnels are torn down.
	// It runs on the main thread; the IPC calls below don't need it.
	var (
		shutdownOnce sync.Once
		bridge       *eventBridge // assigned below; nil-checked
	)
	doShutdown := func() {
		shutdownOnce.Do(func() {
			slog.Info("shutting down GUI + helper")
			// Stop forwarding helper events first: the main thread is busy
			// here, so tray/UI updates from the bridge would block its event
			// loop while the helper is still streaming status during teardown.
			if bridge != nil {
				bridge.stopForwarding()
			}
			// Close open history sessions BEFORE disconnecting so GetStatus
			// still reports last-known rx/tx.
			wgapp.CloseHistorySessions(tunnelService, "app_quit")
			// Disconnect EVERY active tunnel by name (the helper rejects
			// nameless disconnects). callLong gives each its own 60 s budget.
			// If the helper is unreachable there is nothing to tear down from
			// here; its own grace-window timer handles a dropped GUI.
			//
			// Do NOT send MethodShutdown: the LaunchDaemon (KeepAlive=true)
			// would be respawned by launchd immediately, producing a restart
			// loop on every quit.
			if names, err := wgapp.ActiveTunnelNames(tunnelService); err == nil {
				for _, name := range names {
					if err := tunnelService.DisconnectTunnel(name); err != nil {
						slog.Warn("shutdown: disconnect failed", "tunnel", name, "error", err)
					}
				}
			} else {
				slog.Warn("shutdown: cannot list active tunnels", "error", err)
			}
			clients.Close()
		})
	}

	// 5. Wails app
	app := application.New(application.Options{
		Name:        "LockPlus",
		Description: "WireGuard and OpenVPN client for macOS",
		Services: []application.Service{
			application.NewService(tunnelService),
		},
		Assets: application.AssetOptions{
			Handler: assetsHandler,
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
		OnShutdown: doShutdown,
	})
	wgapp.SetApp(tunnelService, app)
	bindAppToLogHandler(app)

	// Register the log event shape so Wails knows how to marshal it.
	application.RegisterEvent[ipc.LogEntry]("log")

	// 6. Main window
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
	wgapp.SetWindow(tunnelService, win)
	dockWindow = win

	// Native file drop forwarded to frontend
	win.OnWindowEvent(events.Common.WindowFilesDropped, func(event *application.WindowEvent) {
		files := event.Context().DroppedFiles()
		// Authorize exactly these paths (single use, short TTL) for the
		// path-taking bindings the frontend calls in response.
		wgapp.GrantPaths(tunnelService, files)
		app.Event.Emit("files-dropped", map[string]any{"files": files})
	})

	// 7. System tray — always use SetIcon (never SetTemplateIcon) to avoid
	// a Wails v3 bug where the isTemplateIcon sticky flag makes all
	// subsequent SetIcon calls render as monochrome template icons.
	tray := app.SystemTray.New()
	tray.SetIcon(trayOffIcon)
	tray.SetTooltip("LockPlus")

	trayMgr := newTrayManager(app, win, tray, tunnelService)
	trayMgr.initialBuild()

	// 8. IPC event bridge + helper health monitor.
	// The bridge owns the subscription and re-subscribes when the helper
	// process restarts. The health monitor swaps the client in the holder.
	// Pass the tray's cheap icon-update hook — NOT the full menu rebuild —
	// so the 1 Hz status stream doesn't trigger IPC round-trips on every event.
	//
	// The bridge tolerates a nil client (resubscribe is a no-op until the
	// holder has one), so we can construct it before the helper is ready.
	bridge = newEventBridge(app, clients, trayMgr.updateStatus, func(active []string, rx, tx map[string]int64, reason string) {
		wgapp.ReconcileHistoryFromStatus(tunnelService, active, rx, tx, reason)
	})
	bridge.start()

	healthDone := make(chan struct{})
	var healthWg sync.WaitGroup
	healthWg.Add(1)
	startHelperHealthMonitor(app, clients, settingsStore, dataDir, bridge, healthDone, &healthWg)

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
			go wgapp.MigrateAutostart(tunnelService)
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
		var sigErr *elevate.SignatureError
		if errors.As(err, &sigErr) {
			slog.Error("helper install refused: code signature verification failed", "output", sigErr.Output)
			showSignatureFailureDialog()
			app.Quit()
			return
		}
		var bootErr *elevate.BootstrapError
		if errors.As(err, &bootErr) {
			slog.Error("launchd blocked the helper daemon", "output", bootErr.Output)
			blockedCmd := `display dialog "macOS blocked LockPlus's background helper service.\n\nOpen System Settings → General → Login Items & Extensions, find LockPlus, and turn it ON. Then relaunch LockPlus.\n\nIf LockPlus is not listed, restart your Mac and try again." buttons {"Open Login Items", "Quit"} default button "Open Login Items" with title "LockPlus" with icon stop`
			out, _ := exec.Command("/usr/bin/osascript", "-e", blockedCmd).Output()
			if strings.Contains(string(out), "Open Login Items") {
				// x-apple.systempreferences URL for the Login Items pane.
				_ = exec.Command("/usr/bin/open", "x-apple.systempreferences:com.apple.LoginItems-Settings.extension").Run()
			}
			app.Quit()
			return
		}

		if attempt < 2 {
			retryCmd := `display dialog "LockPlus needs its helper service to manage VPN connections.\n\nPlease grant administrator access when prompted." buttons {"Quit", "Retry"} default button "Retry" with title "LockPlus" with icon caution`
			out, retryErr := exec.Command("/usr/bin/osascript", "-e", retryCmd).Output()
			if retryErr != nil || strings.Contains(string(out), "Quit") {
				slog.Error("helper setup cancelled by user")
				app.Quit()
				return
			}
			continue
		}
		slog.Error("helper connection failed after 3 attempts", "error", err)
		failCmd := `display dialog "LockPlus could not start its helper service.\n\nPlease quit any other running copies of LockPlus and try again." buttons {"Quit"} default button "Quit" with title "LockPlus" with icon stop`
		_, _ = exec.Command("/usr/bin/osascript", "-e", failCmd).Output()
		app.Quit()
		return
	}

	// Push the persisted policy BEFORE installing the client: until Set, no
	// tray, Wi-Fi rule or frontend connect can reach this helper, so none
	// can slip in under the helper's default (kill switch off) policy.
	// Resubscribe (capitalised) then emits "helper_reset" so the frontend
	// reloads tunnel state from a fresh helper.
	pushPersistedSettings(newClient, settingsStore)
	clients.Set(newClient)
	bridge.Resubscribe()

	// Notify the frontend that helper IPC is now available. App.svelte uses
	// this to dismiss the connecting toast.
	app.Event.Emit("helper", HelperEvent{Alive: true})
	slog.Info("helper bootstrap complete")
}

// pushPersistedSettings sends the helper-side settings (log level, kill
// switch and DNS protection policy, health check, interface pinning) to a
// freshly connected helper. Called after the initial bootstrap and after
// every recovery, before the client is installed: a restarted helper starts
// from its defaults, and the persisted settings are the source of truth.
func pushPersistedSettings(c *ipc.Client, settingsStore *storage.SettingsStore) {
	s, err := settingsStore.Load()
	if err != nil || s == nil {
		slog.Warn("cannot load settings to push to helper", "error", err)
		return
	}
	if s.LogLevel != "" {
		_ = c.Call(ipc.MethodSetLogLevel, ipc.SetLogLevelRequest{Level: s.LogLevel}, nil)
	}
	if err := wgapp.PushFirewallPolicy(c, s); err != nil {
		slog.Warn("pushing firewall policy to helper failed", "error", err)
	}
	if err := c.Call(ipc.MethodSetHealthCheck, ipc.SetHealthCheckRequest{Enabled: s.HealthCheck}, nil); err != nil {
		slog.Warn("pushing health check setting to helper failed", "error", err)
	}
	if err := c.Call(ipc.MethodSetPinInterface, ipc.SetPinInterfaceRequest{Enabled: s.PinInterface}, nil); err != nil {
		slog.Warn("pushing pin-interface setting to helper failed", "error", err)
	}
}
