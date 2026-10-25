package ovpn

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func startSleep(t *testing.T) (*exec.Cmd, chan struct{}) {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return cmd, exited
}

// A pid file left by a dead helper gets its openvpn killed, but only when
// the pid's executable is our binary; the pid file is consumed either way.
func TestKillStaleProcesses(t *testing.T) {
	dir := t.TempDir()
	ours, oursExited := startSleep(t)
	other, otherExited := startSleep(t)
	if err := writePIDFile(filepath.Join(dir, "work"+pidSuffix), ours.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if err := writePIDFile(filepath.Join(dir, "home"+pidSuffix), other.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if exe, err := procExecPath(ours.Process.Pid); err != nil || exe != "/bin/sleep" {
		t.Fatalf("procExecPath = %q, %v", exe, err)
	}

	if got := KillStaleProcesses(dir, "/bin/sleep"); !slices.Equal(got, []string{"home", "work"}) && !slices.Equal(got, []string{"work", "home"}) {
		t.Fatalf("killed %v", got)
	}
	for _, exited := range []chan struct{}{oursExited, otherExited} {
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Fatal("process not killed")
		}
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*"+pidSuffix)); len(files) != 0 {
		t.Fatalf("pid files left: %v", files)
	}

	survivor, survivorExited := startSleep(t)
	if err := writePIDFile(filepath.Join(dir, "x"+pidSuffix), survivor.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if got := KillStaleProcesses(dir, "/Library/PrivilegedHelperTools/openvpn"); len(got) != 0 {
		t.Fatalf("killed a process that isn't our openvpn: %v", got)
	}
	select {
	case <-survivorExited:
		t.Fatal("unrelated process was killed")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestReadPIDFileRejectsInsecure(t *testing.T) {
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose.pid")
	if err := os.WriteFile(loose, []byte("1234\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPIDFile(loose); err == nil {
		t.Error("group/world-readable pid file accepted")
	}
	link := filepath.Join(dir, "link.pid")
	if err := os.Symlink(loose, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPIDFile(link); err == nil {
		t.Error("symlinked pid file accepted")
	}
	if fi, err := os.Stat(loose); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.pid")
	if err := writePIDFile(good, 4321); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(good); fi.Mode().Perm() != 0o600 {
		t.Errorf("pid file mode %v, want 0600", fi.Mode().Perm())
	}
	if pid, err := readPIDFile(good); err != nil || pid != 4321 {
		t.Errorf("readPIDFile = %d, %v", pid, err)
	}
}
