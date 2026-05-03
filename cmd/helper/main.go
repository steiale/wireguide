// Command helper is the privileged background service for WireGuide+.
//
// This is a minimal binary that ONLY imports internal/helper — deliberately
// excluding the Wails/AppKit/WebKit GUI stack so it can run as a root
// LaunchDaemon without a window server (those frameworks crash in headless
// context when run as root).
package main

import (
	"flag"
	"log"
	"os"
	"runtime"

	"github.com/steiale/wireguide/internal/helper"
)

func main() {
	// --helper is accepted but unused: the GUI binary used this flag to switch
	// between GUI and helper modes in a single binary. This binary is always the
	// helper, so the flag is a no-op kept for backward compatibility with plists
	// written by older GUI versions.
	flag.Bool("helper", false, "no-op: this binary is always the helper")
	socketPath := flag.String("socket", "", "socket path for IPC")
	socketUID := flag.Int("uid", -1, "socket owner UID")
	dataDir := flag.String("data-dir", "", "data directory")
	flag.Parse()

	if *socketPath == "" {
		log.Fatal("--socket required in helper mode")
	}
	if *dataDir == "" {
		*dataDir = systemDataDir()
	}
	log.Println("WireGuide helper starting...")
	if err := helper.Run(*socketPath, *socketUID, *dataDir); err != nil {
		log.Fatal("helper error:", err)
	}
}

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
