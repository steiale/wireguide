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

	req := `-R='anchor apple generic and certificate leaf[subject.OU] = "M53GHX9FAY"'`
	if n := strings.Count(script, "/usr/bin/codesign --verify --strict "+req); n != 2 {
		t.Fatalf("expected 2 codesign checks (helper + openvpn), got %d\n%s", n, script)
	}
	for _, dst := range []string{daemonBinary, "/Library/PrivilegedHelperTools/openvpn"} {
		cp := strings.Index(script, "cp -f ")
		verify := strings.Index(script, req+" "+shellQuote(dst))
		if verify < 0 || verify < cp {
			t.Errorf("codesign check for %s missing or before copy", dst)
		}
		if !strings.Contains(script, "/bin/rm -f "+shellQuote(dst)+`; echo "SIGNATURE_INVALID`) {
			t.Errorf("signature failure for %s must delete the destination and emit SIGNATURE_INVALID", dst)
		}
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

// The verify snippet must reject an unsigned binary, delete it and exit 5
// with the marker. Runs codesign against a scratch file only.
func TestVerifySignatureSnippetRejectsUnsigned(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "fake-helper")
	if err := os.WriteFile(dst, []byte("#!/bin/sh\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "set -e; "+verifySignatureSnippet(dst)+"echo REACHED")
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
