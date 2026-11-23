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
		for _, want := range []string{"Go resolver", "has been removed", "dnsdist", "docs/PRODUCTION.md"} {
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
		{}, // unset means dnsdist
	} {
		if out, code := guard(t, "", env...); code != 0 {
			t.Errorf("%v: exit %d: %s", env, code, out)
		}
	}
}

// POWERSVX_ALLOW_LEGACY_DATAPLANE used to let a lab keep the Go resolver. No
// code remains to run it, so the variable no longer changes anything.
func TestGuardEscapeHatchIsVoid(t *testing.T) {
	for _, mode := range []string{"powersvx", "bogus", "unbound", "external"} {
		for _, hatch := range []string{"1", "0", ""} {
			out, code := guard(t, "", "POWERSVX_DNS_DATAPLANE="+mode, "POWERSVX_ALLOW_LEGACY_DATAPLANE="+hatch)
			if code == 0 {
				t.Fatalf("%s/%q: the old escape hatch let a removed mode through: %s", mode, hatch, out)
			}
			if strings.Contains(out, "ALLOW_LEGACY") {
				t.Errorf("%s/%q: output mentions the void escape hatch: %s", mode, hatch, out)
			}
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
