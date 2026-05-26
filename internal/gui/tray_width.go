package gui

import "runtime"

// lockTrayWidth sets the system tray status item to a fixed pixel width.
// Must be called on the macOS main thread after the tray is created.
// No-op on non-Darwin platforms.
func lockTrayWidth() {
	if runtime.GOOS != "darwin" {
		return
	}
	lockTrayWidthDarwin()
}
