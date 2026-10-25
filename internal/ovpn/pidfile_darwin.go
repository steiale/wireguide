package ovpn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// pidSuffix names the per-tunnel pid file in the (root-only) runtime dir.
// The helper writes one for every openvpn it starts and removes it in
// cleanup; one left behind means the helper died (SIGKILL, crash) and the
// root openvpn may still be running, holding routes and DNS.
const pidSuffix = ".pid"

// writePIDFile records pid at path, root-only (0600), replacing any file
// (or symlink) already there.
func writePIDFile(path string, pid int) error {
	_ = os.Remove(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(strconv.Itoa(pid) + "\n")
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// readPIDFile reads a pid file, refusing anything that isn't a regular,
// root-only file owned by us: the pid steers a root kill.
func readPIDFile(path string) (int, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return 0, fmt.Errorf("%s owned by uid %d", path, st.Uid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return 0, fmt.Errorf("%s has insecure mode %v", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, fmt.Errorf("%s: invalid pid %q", path, strings.TrimSpace(string(data)))
	}
	return pid, nil
}

// procExecPath returns the executable path of pid from kern.procargs2
// (what proc_pidpath reports): a 4-byte argc followed by the NUL-terminated
// exec path.
func procExecPath(pid int) (string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(buf) < 5 {
		return "", fmt.Errorf("short procargs2 for pid %d", pid)
	}
	_ = binary.LittleEndian.Uint32(buf[:4]) // argc
	rest := buf[4:]
	if i := bytes.IndexByte(rest, 0); i >= 0 {
		rest = rest[:i]
	}
	if len(rest) == 0 {
		return "", fmt.Errorf("no exec path for pid %d", pid)
	}
	return string(rest), nil
}

// processAlive reports whether pid exists (signal 0).
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// KillStaleProcesses terminates openvpn processes a previous helper started
// and never reaped (it was SIGKILLed or crashed), using the pid files in
// runtimeDir. A pid is only signalled if its executable is binaryPath (our
// root-owned PrivilegedHelperTools openvpn), so a recycled pid never kills
// an unrelated process. Call at helper startup, before any Connect. Returns
// the tunnel names whose openvpn was killed.
func KillStaleProcesses(runtimeDir, binaryPath string) []string {
	files, _ := filepath.Glob(filepath.Join(runtimeDir, "*"+pidSuffix))
	var killed []string
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), pidSuffix)
		pid, err := readPIDFile(path)
		_ = os.Remove(path)
		if err != nil {
			slog.Warn("ovpn: ignoring stale pid file", "path", path, "error", err)
			continue
		}
		exe, err := procExecPath(pid)
		if err != nil || filepath.Clean(exe) != filepath.Clean(binaryPath) {
			continue // gone, or the pid now belongs to something else
		}
		slog.Warn("ovpn: killing orphaned openvpn from a previous helper", "tunnel", name, "pid", pid)
		_ = syscall.Kill(pid, syscall.SIGTERM)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && processAlive(pid) {
			time.Sleep(100 * time.Millisecond)
		}
		if processAlive(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		killed = append(killed, name)
	}
	return killed
}
