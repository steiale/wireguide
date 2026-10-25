package wifi

import "sync"

// AuthStatus is the app's Location Services authorization state. Reading
// the Wi-Fi SSID requires AuthAuthorized on current macOS.
type AuthStatus string

const (
	AuthNotDetermined AuthStatus = "notDetermined"
	AuthRestricted    AuthStatus = "restricted"
	AuthDenied        AuthStatus = "denied"
	AuthAuthorized    AuthStatus = "authorized"
)

// LocationAuthStatus returns the current authorization state. Non-blocking.
func LocationAuthStatus() AuthStatus { return nativeAuthStatus() }

// StartLocationObserver creates the long-lived CLLocationManager on the main
// thread so authorization changes (e.g. the user enabling LockPlus in System
// Settings) are delivered to OnLocationAuthChange listeners. Never prompts.
func StartLocationObserver() { nativeStartObserver() }

// RequestLocationAuth shows the system Location prompt if the state is
// notDetermined; otherwise it does nothing. Asynchronous — the outcome is
// delivered to OnLocationAuthChange listeners.
func RequestLocationAuth() { nativeRequestAuth() }

var (
	authMu        sync.Mutex
	authListeners = map[int]func(AuthStatus){}
	authNextID    int
)

// OnLocationAuthChange registers f to be called (on its own goroutine) when
// the authorization state is reported by CoreLocation. Returns an
// unregister func.
func OnLocationAuthChange(f func(AuthStatus)) (unregister func()) {
	authMu.Lock()
	id := authNextID
	authNextID++
	authListeners[id] = f
	authMu.Unlock()
	return func() {
		authMu.Lock()
		delete(authListeners, id)
		authMu.Unlock()
	}
}

func notifyAuthChanged(st AuthStatus) {
	authMu.Lock()
	fs := make([]func(AuthStatus), 0, len(authListeners))
	for _, f := range authListeners {
		fs = append(fs, f)
	}
	authMu.Unlock()
	for _, f := range fs {
		f(st)
	}
}
