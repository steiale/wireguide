//go:build darwin

package gui

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit
#include "tray_width_darwin.h"
*/
import "C"

func lockTrayWidthDarwin() {
	C.setStatusItemFixedWidth(190)
}
