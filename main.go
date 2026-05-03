// WireGuide — GUI binary entrypoint.
//
// This binary runs as the current user and hosts the Wails window + tray.
// The privileged helper is a separate binary (cmd/helper) installed as a
// LaunchDaemon — see cmd/helper/main.go.
//
// main.go is intentionally tiny: bootstrap GUI mode only. GUI runtime lives
// in internal/gui.
package main

import (
	"embed"
	"log"
	"os"
	"runtime"

	"github.com/steiale/wireguide/internal/gui"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	if err := gui.Run(application.AssetFileServerFS(assets), systemDataDir()); err != nil {
		log.Fatal(err)
	}
}

// systemDataDir returns the system-level data directory used by the GUI to
// locate helper-managed state (e.g. crash recovery files written by the
// privileged helper at /Library/Application Support/wireguide on macOS).
func systemDataDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/wireguide"
	case "linux":
		return "/var/lib/wireguide"
	case "windows":
		if pd := os.Getenv("PROGRAMDATA"); pd != "" {
			return pd + `\wireguide`
		}
		return `C:\ProgramData\wireguide`
	}
	return "/tmp/wireguide"
}
