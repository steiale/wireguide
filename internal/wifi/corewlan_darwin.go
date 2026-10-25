//go:build darwin

package wifi

/*
#cgo LDFLAGS: -framework Foundation -framework CoreLocation -framework CoreWLAN
#include <stdlib.h>

void lpLocationStart(void);
void lpLocationRequest(void);
int lpLocationStatus(void);
char *lpWiFiInfo(int *hasIface, int *associated, char **ifname);
*/
import "C"

import (
	"unsafe"
)

// Keep in sync with the enum in corewlan_darwin.m.
func authFromC(st C.int) AuthStatus {
	switch st {
	case 1:
		return AuthRestricted
	case 2:
		return AuthDenied
	case 3:
		return AuthAuthorized
	default:
		return AuthNotDetermined
	}
}

//export goLocationAuthChanged
func goLocationAuthChanged(st C.int) {
	// Runs on the AppKit main thread — never block it.
	go notifyAuthChanged(authFromC(st))
}

func nativeAuthStatus() AuthStatus { return authFromC(C.lpLocationStatus()) }

func nativeStartObserver() { C.lpLocationStart() }

func nativeRequestAuth() { C.lpLocationRequest() }

func nativeWiFiInfo() coreWLANInfo {
	var hasIface, associated C.int
	var ifname *C.char
	cssid := C.lpWiFiInfo(&hasIface, &associated, &ifname)
	info := coreWLANInfo{HasInterface: hasIface != 0, Associated: associated != 0}
	if ifname != nil {
		info.Interface = C.GoString(ifname)
		C.free(unsafe.Pointer(ifname))
	}
	if cssid != nil {
		info.SSID = C.GoString(cssid)
		C.free(unsafe.Pointer(cssid))
	}
	return info
}
