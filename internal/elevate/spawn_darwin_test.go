package elevate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScriptVerifiesSignatures(t *testing.T) {
	script := buildInstallScript("/Applications/LockPlus.app/Contents/MacOS/lockplus-helper", "cGxpc3Q=")

	for dst, id := range map[string]string{daemonBinary: helperIdentifier, "/Library/PrivilegedHelperTools/openvpn": openvpnIdentifier} {
		tmp := shellQuote(dst + ".new")
		req := `-R=` + shellQuote(`anchor apple generic and certificate leaf[subject.OU] = "M53GHX9FAY" and identifier "`+id+`"`)
		cp := strings.Index(script, "(umask 077 && cp ")
		verify := strings.Index(script, req+" "+tmp)
		chmod := strings.Index(script, "chmod 755 "+tmp)
		mv := strings.Index(script, "mv -f "+tmp+" "+shellQuote(dst))
		if cp < 0 || verify < cp || chmod < verify || mv < chmod {
			t.Errorf("%s: want root-only copy, then verify, then chmod 755, then mv (cp=%d verify=%d chmod=%d mv=%d)", dst, cp, verify, chmod, mv)
		}
		if !strings.Contains(script, "/bin/rm -f "+tmp+`; echo "SIGNATURE_INVALID`) {
			t.Errorf("signature failure for %s must delete the copy and emit SIGNATURE_INVALID", dst)
		}
	}
	if strings.Contains(script, "chmod 755 "+shellQuote(daemonBinary)) {
		t.Error("destination must never be made executable before verification")
	}

	logFix := "/bin/chmod 600 " + shellQuote(helperLogPath)
	logIdx := strings.Index(script, logFix)
	bootIdx := strings.Index(script, "launchctl bootstrap")
	if logIdx < 0 || bootIdx < 0 || logIdx > bootIdx {
		t.Errorf("helper log must be chmod 600 before bootstrap")
	}

	// Syntax-check the script with sh -n (parses only, executes nothing).
	if out, err := exec.Command("/bin/sh", "-n", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("install script has a shell syntax error: %v\n%s", err, out)
	}
}

// A symlinked source is refused before anything is copied.
func TestInstallBinarySnippetRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "lockplus-helper")
	if err := os.Symlink("/etc/hosts", src); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "installed")
	out, err := exec.Command("/bin/sh", "-c", "set -e; "+installBinarySnippet(src, dst, helperIdentifier)+"echo REACHED").CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 5 || !strings.Contains(string(out), "SIGNATURE_INVALID") {
		t.Fatalf("expected exit 5 with marker, got %v\n%s", err, out)
	}
	for _, p := range []string{dst, dst + ".new"} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s was created: %v", p, err)
		}
	}
}

// The verify snippet must reject an unsigned binary, delete it and exit 5
// with the marker. Runs codesign against a scratch file only.
func TestVerifySignatureSnippetRejectsUnsigned(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "fake-helper")
	if err := os.WriteFile(dst, []byte("#!/bin/sh\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "set -e; "+verifySignatureSnippet(dst, helperIdentifier)+"echo REACHED")
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 5 {
		t.Fatalf("expected exit 5, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "SIGNATURE_INVALID") || strings.Contains(string(out), "REACHED") {
		t.Fatalf("unexpected output: %s", out)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("unsigned destination was not removed: %v", err)
	}
}

func TestInterpretInstallOutput(t *testing.T) {
	exitErr := errors.New("exit status 5")
	var sigErr *SignatureError
	if err := interpretInstallOutput("SIGNATURE_INVALID: /x: not signed", exitErr); !errors.As(err, &sigErr) {
		t.Fatalf("want *SignatureError, got %T %v", err, err)
	}
	var bootErr *BootstrapError
	if err := interpretInstallOutput("BOOTSTRAP_FAILED: nope", exitErr); !errors.As(err, &bootErr) {
		t.Fatalf("want *BootstrapError, got %T %v", err, err)
	}
	if err := interpretInstallOutput("INSTALL_OK", nil); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}
