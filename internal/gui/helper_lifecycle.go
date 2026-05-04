package gui

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/steiale/wireguide/internal/elevate"
	"github.com/steiale/wireguide/internal/ipc"
	"github.com/steiale/wireguide/internal/update"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// ensureHelper connects to an existing helper (via socket) or spawns a new
// one with privilege elevation. Polls for readiness until the context expires.
func ensureHelper(ctx context.Context, dataDir string) (*ipc.Client, error) {
	addr, err := ipc.DefaultSocketPath()
	if err != nil {
		return nil, fmt.Errorf("resolve socket path: %w", err)
	}
	forceReinstall := false

	// Try an existing helper first (survives GUI restarts).
	if client, err := ipc.NewClient(addr); err == nil {
		// 2 s (not 500 ms): a freshly-spawned helper that's still
		// initialising — replaying state, opening the firewall, taking
		// the connectMu — can legitimately take more than half a second
		// to handle its first ping. A too-tight deadline here causes
		// ensureHelper to give up on a perfectly healthy helper and trip
		// the fallback reinstall path.
		pingCtx, pingCancel := context.WithTimeout(ctx, 2*time.Second)
		var resp ipc.PingResponse
		pingErr := client.CallWithContext(pingCtx, ipc.MethodPing, nil, &resp)
		pingCancel()
		if pingErr == nil {
			guiVersion := update.CurrentVersion()
			helperAppVersion := resp.AppVersion
			if helperAppVersion == "" {
				// Old helper that doesn't have AppVersion field — force upgrade.
				helperAppVersion = "unknown"
			}
			// Detect a daemon that's the OLD combined GUI binary running in
			// --helper mode. The expected daemon binary lives at the
			// PrivilegedHelperTools path (see internal/elevate/spawn_darwin.go
			// daemonBinary). If the running daemon is anywhere else — most
			// commonly /Applications/<App>.app/Contents/MacOS/wireguide-plus
			// (the v1.0.22 single-binary layout) — force reinstall regardless
			// of AppVersion match. Otherwise both binaries fall back to the
			// same compiled-in fallbackVersion and the version check spuriously
			// passes, leaving the old NSWorkspace-based reconnect code path
			// running as root LaunchDaemon (which the v1.0.23 IOKit rewrite
			// was specifically meant to replace).
			const expectedDaemonBinary = "/Library/PrivilegedHelperTools/io.github.steiale.wireguide-plus.helper"
			binaryMismatch := resp.BinaryPath != "" && resp.BinaryPath != expectedDaemonBinary
			if helperAppVersion == guiVersion && !binaryMismatch {
				slog.Info("connected to existing helper",
					"version", helperAppVersion,
					"binary", resp.BinaryPath)
				return client, nil
			}
			if binaryMismatch {
				slog.Warn("helper running from unexpected binary path, forcing reinstall",
					"got", resp.BinaryPath, "want", expectedDaemonBinary)
			}
			// Helper version mismatch — reinstall and let kickstart restart it.
			//
			// Do NOT send Shutdown here. The old helper has KeepAlive=true, so
			// shutting it down causes launchd to immediately respawn the OLD
			// binary. A few hundred ms later we kickstart, which kills the
			// just-respawned helper. If that helper had been alive for less
			// than launchd's ThrottleInterval (default 10 s), launchd refuses
			// to respawn for ~10 s — long enough that the caller may give up.
			//
			// Skipping Shutdown means the old daemon stays alive until the
			// install script runs `launchctl kickstart -k`. That command kills
			// the (long-running) old helper exactly once, after the new binary
			// is already on disk, and launchd respawns the new binary
			// immediately because the previous instance had been up much
			// longer than the throttle window.
			slog.Warn("helper version mismatch, upgrading",
				"helper", helperAppVersion, "gui", guiVersion)
			client.Close()
			// Force reinstall so SpawnHelper skips the "already running"
			// check — installAndLoadDaemon will kickstart the daemon to
			// pick up the new binary.
			forceReinstall = true
		} else {
			client.Close()
		}
	}

	// Spawn new helper with elevation.
	// SpawnHelper runs osascript (admin password prompt) + launchctl internally
	// and has its own timeouts — do not pass the caller's context here since
	// the prompt alone can take 20+ seconds, which would exhaust a 30s budget
	// before the socket poll even starts.
	slog.Info("spawning helper with elevation...")
	args := elevate.Args{
		SocketPath:     addr,
		SocketUID:      os.Getuid(),
		DataDir:        dataDir,
		ForceReinstall: forceReinstall,
	}
	if err := elevate.SpawnHelper(args); err != nil {
		return nil, fmt.Errorf("spawn helper: %w", err)
	}

	// After a successful install give the poll a fresh 60s budget, independent
	// of how long SpawnHelper took (osascript + launchctl can be slow).
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer pollCancel()
	ctx = pollCtx

	// Poll for readiness until the context is cancelled.
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
		client, err := ipc.NewClient(addr)
		if err != nil {
			continue
		}
		var resp ipc.PingResponse
		if err := client.CallWithContext(ctx, ipc.MethodPing, nil, &resp); err == nil {
			// After force reinstall, verify we connected to the NEW helper.
			if forceReinstall && resp.AppVersion != "" && resp.AppVersion != update.CurrentVersion() {
				slog.Debug("polling: still old helper version", "got", resp.AppVersion)
				client.Close()
				continue
			}
			// Also verify the running daemon is the standalone helper binary,
			// not the leftover combined GUI binary from a stale install.
			const expectedDaemonBinary = "/Library/PrivilegedHelperTools/io.github.steiale.wireguide-plus.helper"
			if forceReinstall && resp.BinaryPath != "" && resp.BinaryPath != expectedDaemonBinary {
				slog.Debug("polling: still old helper binary path", "got", resp.BinaryPath)
				client.Close()
				continue
			}
			slog.Info("helper ready", "app_version", resp.AppVersion, "binary", resp.BinaryPath)
			return client, nil
		}
		client.Close()
	}
}

// startHelperHealthMonitor runs a background goroutine that pings the helper
// every 5 seconds. On failure it:
//  1. Emits a "helper" event to notify the frontend
//  2. Attempts to re-spawn the helper and establish a new connection
//  3. Swaps the new connection into the ClientHolder
//  4. Asks the event bridge to re-subscribe
//  5. Emits "helper" (alive) once the connection is back
//
// This fixes the previous design where a helper crash left the app
// permanently unable to receive events (the bridge was still attached to a
// dead socket).
func startHelperHealthMonitor(app *application.App, clients *ipc.ClientHolder, dataDir string, bridge *eventBridge, done <-chan struct{}, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		wasAlive := true
		for {
			select {
			case <-done:
				slog.Info("helper health monitor stopped")
				return
			case <-ticker.C:
			}

			c := clients.Get()
			if c == nil {
				continue // client may be temporarily nil during swap; keep ticking
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			var resp ipc.PingResponse
			err := c.CallWithContext(ctx, ipc.MethodPing, nil, &resp)
			cancel()
			alive := err == nil

			// If a long-running RPC (Connect, Disconnect) is in-flight, the
			// server processes requests sequentially per connection, so our
			// ping won't be read until the RPC finishes. A timeout here does
			// NOT mean the helper is dead — it just means it's busy. Treating
			// this as a failure would trigger recoverHelper, which closes the
			// old client (killing the in-flight RPC), creates a new client,
			// and the server's onDisconnect fires the shutdown timer.
			// This was the root cause of the "helper dies 22-30s after connect" bug.
			if !alive && clients.HasInflight() {
				slog.Debug("health ping timed out but RPC in-flight, skipping")
				continue
			}

			switch {
			case !alive && wasAlive:
				slog.Warn("helper disconnected", "error", err)
				app.Event.Emit("helper", HelperEvent{
					Alive:   false,
					Message: "Helper process not responding: " + err.Error(),
				})
				wasAlive = false

				// Try to recover immediately — don't wait for the next tick.
				if recoverHelper(clients, bridge, dataDir, done) {
					slog.Info("helper recovered")
					app.Event.Emit("helper", HelperEvent{Alive: true})
					wasAlive = true
				}

			case !alive && !wasAlive:
				// Retry recovery on subsequent ticks until it comes back.
				if recoverHelper(clients, bridge, dataDir, done) {
					slog.Info("helper recovered")
					app.Event.Emit("helper", HelperEvent{Alive: true})
					wasAlive = true
				}

			case alive && !wasAlive:
				// Unexpected: ping succeeded without a recoverHelper call.
				// Happens if a new helper accepted the old socket somehow.
				slog.Info("helper reachable again")
				app.Event.Emit("helper", HelperEvent{Alive: true})
				wasAlive = true
			}
		}
	}()
}

// recoverHelper attempts to re-establish a working helper connection. Returns
// true if a new client is now in place. Best-effort — caller decides whether
// to retry on the next tick.
func recoverHelper(clients *ipc.ClientHolder, bridge *eventBridge, dataDir string, done <-chan struct{}) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Allow early exit when shutdown is requested: cancel the context
	// so ensureHelper's polling loop terminates promptly.
	earlyExit := make(chan struct{})
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		case <-earlyExit:
		}
	}()
	defer close(earlyExit)

	newClient, err := ensureHelper(ctx, dataDir)
	if err != nil {
		slog.Debug("helper recovery attempt failed", "error", err)
		return false
	}
	clients.Set(newClient)
	bridge.Resubscribe()
	return true
}
