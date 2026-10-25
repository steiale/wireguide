//go:build darwin

// CoreWLAN SSID lookup + CoreLocation authorization for the GUI process.
//
// Since macOS 14.4 (and partially earlier) CWInterface.ssid, `ipconfig
// getsummary` and friends return nil / "<redacted>" unless the calling app
// holds Location Services authorization (CWInterface.h: "SSID information is
// not available unless Location Services is enabled and the user has
// authorized the calling app to use location services").
//
// Threading: the CLLocationManager is created on, and only ever touched
// from, the main thread (its delegate callbacks are delivered on the run loop
// of the thread that created it, and Wails runs the AppKit main loop there).
// It is retained for the life of the process — releasing a manager while its
// authorization prompt is up silently cancels the prompt.
//
// Compiled without ARC, like the repo's other .m files.

#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>
#import <CoreWLAN/CoreWLAN.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

// Implemented in Go (corewlan_darwin.go). Called on the main thread.
extern void goLocationAuthChanged(int status);

// Status codes shared with Go (keep in sync with corewlan_darwin.go).
enum {
	kLPAuthNotDetermined = 0,
	kLPAuthRestricted = 1,
	kLPAuthDenied = 2,
	kLPAuthAuthorized = 3,
};

static int lpMapStatus(CLAuthorizationStatus s) {
	switch (s) {
	case kCLAuthorizationStatusRestricted:
		return kLPAuthRestricted;
	case kCLAuthorizationStatusDenied:
		return kLPAuthDenied;
	case kCLAuthorizationStatusAuthorizedAlways:
	// On macOS a When-In-Use grant is reported as AuthorizedAlways; the
	// WhenInUse symbol (raw value 4) is marked unavailable in the macOS SDK,
	// but accept the raw value defensively.
	case (CLAuthorizationStatus)4:
		return kLPAuthAuthorized;
	case kCLAuthorizationStatusNotDetermined:
	default:
		return kLPAuthNotDetermined;
	}
}

@interface LPLocationDelegate : NSObject <CLLocationManagerDelegate>
@end

// Main-thread only. Never released (see file comment).
static CLLocationManager *gManager = nil;
static LPLocationDelegate *gDelegate = nil;
// Last status reported by the delegate; -1 until the manager exists.
static atomic_int gStatus = -1;

@implementation LPLocationDelegate
// macOS 11+. Called once right after the manager is created (with the
// current status) and again on every change — including the user flipping
// the toggle in System Settings while the app keeps running.
- (void)locationManagerDidChangeAuthorization:(CLLocationManager *)manager {
	int st = lpMapStatus(manager.authorizationStatus);
	atomic_store(&gStatus, st);
	goLocationAuthChanged(st);
}

- (void)locationManager:(CLLocationManager *)manager didFailWithError:(NSError *)error {
	// Required to avoid console noise when authorization is denied; we
	// never start location updates, so there is nothing to handle.
}
@end

// Must run on the main thread.
static void lpEnsureManager(void) {
	if (gManager != nil) {
		return;
	}
	gDelegate = [[LPLocationDelegate alloc] init];
	gManager = [[CLLocationManager alloc] init];
	gManager.delegate = gDelegate; // delegate is weak/assign: gDelegate keeps it alive
	atomic_store(&gStatus, lpMapStatus(gManager.authorizationStatus));
}

// lpLocationStart creates the long-lived manager on the main queue so that
// authorization changes are observed. Never prompts.
void lpLocationStart(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		lpEnsureManager();
	});
}

// lpLocationRequest asks for When-In-Use authorization (macOS 10.15+). It is
// a no-op unless the status is notDetermined; the result arrives via
// locationManagerDidChangeAuthorization. The app must be frontmost for the
// prompt to appear.
void lpLocationRequest(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		lpEnsureManager();
		if (gManager.authorizationStatus == kCLAuthorizationStatusNotDetermined) {
			[gManager requestWhenInUseAuthorization];
		}
	});
}

// lpLocationStatus returns the current authorization status. Safe from any
// thread: uses the delegate-maintained cache once the manager exists, and the
// (deprecated but thread-safe, non-blocking) class accessor before that.
int lpLocationStatus(void) {
	int st = atomic_load(&gStatus);
	if (st >= 0) {
		return st;
	}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	return lpMapStatus([CLLocationManager authorizationStatus]);
#pragma clang diagnostic pop
}

// lpWiFiInfo reads the default Wi-Fi interface via CoreWLAN. Any thread.
//   *hasIface   1 if a Wi-Fi interface exists
//   *associated 1 if the interface is in station mode (joined a network) —
//               interfaceMode does not need Location authorization
//   return      malloc'd UTF-8 SSID (caller frees), or NULL when not
//               associated / not authorized
//   *ifname     malloc'd BSD name ("en0"), or NULL
char *lpWiFiInfo(int *hasIface, int *associated, char **ifname) {
	*hasIface = 0;
	*associated = 0;
	*ifname = NULL;
	char *out = NULL;
	@autoreleasepool {
		CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
		if (iface == nil) {
			return NULL;
		}
		*hasIface = 1;
		NSString *name = iface.interfaceName;
		if (name != nil && name.length > 0) {
			*ifname = strdup(name.UTF8String);
		}
		*associated = (iface.powerOn && iface.interfaceMode == kCWInterfaceModeStation) ? 1 : 0;
		NSString *ssid = iface.ssid;
		if (ssid != nil && ssid.length > 0) {
			const char *u = ssid.UTF8String;
			if (u != NULL) {
				out = strdup(u);
			}
		}
	}
	return out;
}
