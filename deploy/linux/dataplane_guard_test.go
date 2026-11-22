package linux_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// guard copies dataplane-guard.sh into a temp directory and runs it with sh.
// dir holds an optional .env; the environment is exactly env.
func guard(t *testing.T, dotenv string, env ...string) (string, int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	src, err := os.ReadFile("dataplane-guard.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "dataplane-guard.sh")
	if err := os.WriteFile(script, src, 0o755); err != nil {
		t.Fatal(err)
	}
	if dotenv != "" {
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(dotenv), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", script, dir)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func TestGuardRefusesRemovedUnboundMode(t *testing.T) {
	for _, mode := range []string{"unbound", "external", "UNBOUND"} {
		out, code := guard(t, "", "POWERSVX_DNS_DATAPLANE="+mode)
		if code == 0 {
			t.Errorf("%s: expected non-zero exit, output: %s", mode, out)
		}
		for _, want := range []string{"has been removed", "dnsdist", "docs/PRODUCTION.md"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: output lacks %q: %s", mode, want, out)
			}
		}
	}
}

func TestGuardRefusesGoResolver(t *testing.T) {
	for _, mode := range []string{"powersvx", "bogus"} {
		out, code := guard(t, "", "POWERSVX_DNS_DATAPLANE="+mode)
		if code == 0 {
			t.Errorf("%s: expected non-zero exit, output: %s", mode, out)
		}
		for _, want := range []string{"next major version", "dnsdist", "docs/PRODUCTION.md"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: output lacks %q: %s", mode, want, out)
			}
		}
	}
}

func TestGuardAcceptsDnsdist(t *testing.T) {
	for _, env := range [][]string{
		{"POWERSVX_DNS_DATAPLANE=dnsdist"},
		{"POWERSVX_DNS_DATAPLANE=cdb"},
		{}, // unset on a host deployment means dnsdist
	} {
		if out, code := guard(t, "", env...); code != 0 {
			t.Errorf("%v: exit %d: %s", env, code, out)
		}
	}
}

func TestGuardEscapeHatch(t *testing.T) {
	// The Go resolver can still be run in a lab.
	out, code := guard(t, "", "POWERSVX_DNS_DATAPLANE=powersvx", "POWERSVX_ALLOW_LEGACY_DATAPLANE=1")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if _, code := guard(t, "", "POWERSVX_DNS_DATAPLANE=powersvx", "POWERSVX_ALLOW_LEGACY_DATAPLANE=0"); code == 0 {
		t.Fatal("escape hatch must be exactly 1")
	}
}

// The Unbound-on-the-public-port mode has no code left, so the escape hatch
// must not wave it through, and must say so.
func TestGuardEscapeHatchDoesNotApplyToRemovedUnboundMode(t *testing.T) {
	for _, mode := range []string{"unbound", "external"} {
		out, code := guard(t, "", "POWERSVX_DNS_DATAPLANE="+mode, "POWERSVX_ALLOW_LEGACY_DATAPLANE=1")
		if code == 0 {
			t.Fatalf("%s: escape hatch let the removed mode through: %s", mode, out)
		}
		if !strings.Contains(out, "POWERSVX_ALLOW_LEGACY_DATAPLANE does not bring it back") {
			t.Errorf("%s: output does not say the escape hatch is void: %s", mode, out)
		}
	}
}

func TestGuardReadsModeFromDotEnvLikeCompose(t *testing.T) {
	if out, code := guard(t, "OTHER=1\nPOWERSVX_DNS_DATAPLANE=unbound\n"); code == 0 {
		t.Fatalf("expected refusal from .env, output: %s", out)
	}
	if out, code := guard(t, "POWERSVX_DNS_DATAPLANE=dnsdist\n"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	// the environment wins over .env, as it does for compose
	if out, code := guard(t, "POWERSVX_DNS_DATAPLANE=unbound\n", "POWERSVX_DNS_DATAPLANE=dnsdist"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
}
