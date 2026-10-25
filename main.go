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
// privileged helper at /Library/Application Support/lockplus on macOS).
func systemDataDir() string {
	return "/Library/Application Support/lockplus"
}
