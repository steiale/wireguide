//go:build darwin

package reconnect

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation

#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <stdlib.h>

extern void goWakeCallback(void *ctx);

typedef struct {
	void               *ctx;
	io_connect_t        rootPort;
	IONotificationPortRef notifyPort;
	io_object_t         notifier;
	CFRunLoopRef        runLoop;
} PowerWatcher;

// powerCallback is the IOKit power-event handler. It MUST call
// IOAllowPowerChange for sleep/can-sleep messages or the system will stall
// for 30 seconds before forcibly sleeping.
static void powerCallback(void *refcon, io_service_t service,
                          natural_t messageType, void *messageArgument) {
	PowerWatcher *w = (PowerWatcher *)refcon;
	switch (messageType) {
	case kIOMessageSystemWillSleep:
	case kIOMessageCanSystemSleep:
		IOAllowPowerChange(w->rootPort, (long)messageArgument);
		break;
	case kIOMessageSystemHasPoweredOn:
		goWakeCallback(w->ctx);
		break;
	}
}

static void *runLoopThread(void *arg) {
	PowerWatcher *w = (PowerWatcher *)arg;
	w->runLoop = CFRunLoopGetCurrent();
	CFRunLoopAddSource(w->runLoop,
		IONotificationPortGetRunLoopSource(w->notifyPort),
		kCFRunLoopDefaultMode);
	CFRunLoopRun();
	return NULL;
}

// startPowerWatcher registers for system power events and starts a dedicated
// pthread to run the CFRunLoop. Works in any bootstrap namespace (including
// root LaunchDaemons) — communicates via Mach IPC to powerd, no window server
// required. Returns NULL on failure.
static PowerWatcher *startPowerWatcher(void *ctx) {
	PowerWatcher *w = (PowerWatcher *)calloc(1, sizeof(PowerWatcher));
	if (!w) return NULL;
	w->ctx = ctx;
	w->rootPort = IORegisterForSystemPower(w, &w->notifyPort, powerCallback, &w->notifier);
	if (w->rootPort == MACH_PORT_NULL) {
		free(w);
		return NULL;
	}
	pthread_t tid;
	if (pthread_create(&tid, NULL, runLoopThread, w) != 0) {
		IODeregisterForSystemPower(&w->notifier);
		IONotificationPortDestroy(w->notifyPort);
		IOServiceClose(w->rootPort);
		free(w);
		return NULL;
	}
	pthread_detach(tid);
	return w;
}

static void stopPowerWatcher(PowerWatcher *w) {
	if (!w) return;
	if (w->runLoop) CFRunLoopStop(w->runLoop);
	if (w->notifier) IODeregisterForSystemPower(&w->notifier);
	if (w->notifyPort) IONotificationPortDestroy(w->notifyPort);
	if (w->rootPort) IOServiceClose(w->rootPort);
	free(w);
}
*/
import "C"

import (
	"log/slog"
	"sync"
	"time"
	"unsafe"
)

// darwinSleepDetector detects sleep/wake on macOS using two mechanisms:
//  1. IOKit IORegisterForSystemPower — works in root LaunchDaemons (no window
//     server required; communicates via Mach IPC to powerd directly).
//  2. Wall-clock polling as fallback — catches any events the IOKit path misses.
type darwinSleepDetector struct {
	mu      sync.Mutex
	wakeCh  chan struct{}
	stopCh  chan struct{}
	watcher *C.PowerWatcher
	handle  uintptr
}

func NewSleepDetector() SleepDetector {
	return &darwinSleepDetector{
		wakeCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
}

func (d *darwinSleepDetector) Start() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopCh = make(chan struct{})

	d.handle = registerDetector(d)
	// Cast the numeric handle to unsafe.Pointer — it is an opaque integer
	// token, not a Go pointer, so cgo pointer rules don't apply.
	//nolint:govet
	ctx := *(*unsafe.Pointer)(unsafe.Pointer(&d.handle))
	d.watcher = C.startPowerWatcher(ctx)
	if d.watcher == nil {
		slog.Warn("IOKit power watcher failed to start; relying on poll fallback")
	}

	go d.poll()
}

func (d *darwinSleepDetector) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}
	if d.watcher != nil {
		C.stopPowerWatcher(d.watcher)
		d.watcher = nil
	}
	if d.handle != 0 {
		unregisterDetector(d.handle)
		d.handle = 0
	}
}

func (d *darwinSleepDetector) WakeChan() <-chan struct{} {
	return d.wakeCh
}

func (d *darwinSleepDetector) sendWake() {
	select {
	case d.wakeCh <- struct{}{}:
	default:
	}
}

func (d *darwinSleepDetector) poll() {
	lastCheck := time.Now()
	const pollInterval = 10 * time.Second
	const sleepThreshold = 30 * time.Second

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(lastCheck)
			lastCheck = now
			if elapsed > pollInterval+sleepThreshold {
				slog.Info("sleep/wake detected via polling fallback",
					"expected", pollInterval,
					"actual", elapsed.Round(time.Second))
				d.sendWake()
			}
		}
	}
}

var (
	wakeDetectorsMu  sync.Mutex
	wakeDetectors    = make(map[uintptr]*darwinSleepDetector)
	wakeDetectorNext uintptr
)

func registerDetector(d *darwinSleepDetector) uintptr {
	wakeDetectorsMu.Lock()
	wakeDetectorNext++
	h := wakeDetectorNext
	wakeDetectors[h] = d
	wakeDetectorsMu.Unlock()
	return h
}

func unregisterDetector(h uintptr) {
	wakeDetectorsMu.Lock()
	delete(wakeDetectors, h)
	wakeDetectorsMu.Unlock()
}

//export goWakeCallback
func goWakeCallback(ctx unsafe.Pointer) {
	h := uintptr(ctx)
	wakeDetectorsMu.Lock()
	d, ok := wakeDetectors[h]
	wakeDetectorsMu.Unlock()
	if !ok {
		return
	}
	slog.Info("sleep/wake detected via IOKit power notification")
	d.sendWake()
}
