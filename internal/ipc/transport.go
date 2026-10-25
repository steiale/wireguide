package ipc

// DefaultSocketPath returns the default socket address.
//
// The helper runs as root (via LaunchDaemon or osascript) and creates
// /var/run/lockplus/. The GUI connects as an unprivileged user; the helper
// chowns the socket so the GUI can read/write it. This path is stable across
// app restarts and doesn't pollute the user's home directory.
func DefaultSocketPath() (string, error) {
	return "/var/run/lockplus/lockplus.sock", nil
}
