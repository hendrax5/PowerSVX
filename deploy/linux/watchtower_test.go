package linux_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The log lines are the ones a lab node printed for the scheduled run.
const watchtower401Log = `time="2026-11-20T03:15:00+07:00" level=warning msg="Digest retrieval failed, falling back to full pull" error="... status 401 Unauthorized"
time="2026-11-20T03:15:01+07:00" level=warning msg="Could not pull image" error="... error from registry: unauthorized"
time="2026-11-20T03:15:01+07:00" level=info msg="Update session completed" failed=0 scanned=0 skipped=1 updated=0
`

const watchtowerHealthyLog = `time="2026-11-20T03:15:00+07:00" level=info msg="Found new image" image=ghcr.io/hendrax5/powersvx:latest
time="2026-11-20T03:15:09+07:00" level=info msg="Update session completed" failed=0 scanned=1 skipped=0 updated=1
`

// runWithFakes runs one deploy/linux script with fake docker and curl on the PATH.
// docker prints dockerLog for "docker logs" (exit dockerRC); curl answers the
// anonymous token request and then the manifest request with manifestCode.
func runWithFakes(t *testing.T, script string, args []string, dotenv, dockerLog string, dockerRC int, manifestCode string, env ...string) (string, int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string, mode os.FileMode) {
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, script), string(src), 0o755)
	write(filepath.Join(dir, "docker.log"), dockerLog, 0o644)
	write(filepath.Join(bin, "docker"), "#!/bin/sh\ncat \""+dir+"/docker.log\"\nexit "+itoa(dockerRC)+"\n", 0o755)
	write(filepath.Join(bin, "curl"), `#!/bin/sh
case "$*" in
  *"/token?"*) echo '{"token":"anon-secret-token"}' ;;
  *) printf '%s' "`+manifestCode+`" ;;
esac
`, 0o755)
	if dotenv != "" {
		write(filepath.Join(dir, ".env"), dotenv, 0o600)
	}
	cmd := exec.Command("sh", append([]string{filepath.Join(dir, script)}, args...)...)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + dir}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func itoa(n int) string { return string(rune('0' + n)) }

func TestWatchtowerHealthWarnsOnUnauthorized(t *testing.T) {
	out, code := runWithFakes(t, "watchtower-health.sh", nil, "", watchtower401Log, 0, "")
	if code != 0 {
		t.Fatalf("must exit 0, got %d: %s", code, out)
	}
	for _, want := range []string{"WARNING", "does NOT auto-update", "401 Unauthorized", "Could not pull image", "read:packages", "make the GitHub package public"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestWatchtowerHealthEachPattern(t *testing.T) {
	for _, line := range []string{
		`level=warn msg="Digest retrieval failed" error="status 401 Unauthorized"`,
		`level=warn msg="x" error="denied: permission_denied"`,
		`level=warn msg="Could not pull image"`,
		`level=warn msg="x" error="error from registry: unauthorized"`,
	} {
		out, code := runWithFakes(t, "watchtower-health.sh", nil, "", line+"\n", 0, "")
		if code != 0 || !strings.Contains(out, "WARNING") {
			t.Errorf("%s: exit %d, output %s", line, code, out)
		}
	}
}

func TestWatchtowerHealthHealthyLogIsQuiet(t *testing.T) {
	out, code := runWithFakes(t, "watchtower-health.sh", nil, "", watchtowerHealthyLog, 0, "")
	if code != 0 || strings.Contains(out, "WARNING") || !strings.Contains(out, "OK") {
		t.Errorf("exit %d, output %s", code, out)
	}
}

func TestWatchtowerHealthEmptyLogIsNotAWarning(t *testing.T) {
	out, code := runWithFakes(t, "watchtower-health.sh", nil, "", "", 0, "")
	if code != 0 || strings.Contains(out, "WARNING") {
		t.Errorf("exit %d, output %s", code, out)
	}
}

func TestWatchtowerHealthMissingContainerWarnsButExitsZero(t *testing.T) {
	out, code := runWithFakes(t, "watchtower-health.sh", nil, "", "Error: No such container: powersvx-watchtower\n", 1, "")
	if code != 0 || !strings.Contains(out, "WARNING") || !strings.Contains(out, "not found") {
		t.Errorf("exit %d, output %s", code, out)
	}
}

func TestPreflightPublicImageIsQuiet(t *testing.T) {
	cfg := t.TempDir()
	out, code := runWithFakes(t, "registry-preflight.sh", []string{"."}, "", "", 0, "200", "DOCKER_CONFIG_DIR="+cfg)
	if code != 0 || strings.Contains(out, "WARNING") || !strings.Contains(out, "anonymously") {
		t.Errorf("exit %d, output %s", code, out)
	}
}

func TestPreflightPrivateWithoutCredentialsWarns(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "missing")
	out, code := runWithFakes(t, "registry-preflight.sh", []string{"."}, "", "", 0, "401", "DOCKER_CONFIG_DIR="+cfg)
	if code != 0 {
		t.Fatalf("must exit 0, got %d: %s", code, out)
	}
	for _, want := range []string{"WARNING", "will NOT auto-update", "does not exist", "make the GitHub package", "read:packages", "GHCR_TOKEN configured here: no"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "anon-secret-token") {
		t.Errorf("a token was printed:\n%s", out)
	}
}

func TestPreflightPrivateWithLoginIsOK(t *testing.T) {
	cfg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg, "config.json"), []byte(`{"auths":{"ghcr.io":{"auth":"c2VjcmV0"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runWithFakes(t, "registry-preflight.sh", []string{"."}, "", "", 0, "401", "DOCKER_CONFIG_DIR="+cfg)
	if code != 0 || strings.Contains(out, "WARNING") || !strings.Contains(out, "holds a ghcr.io login") {
		t.Errorf("exit %d, output %s", code, out)
	}
	if strings.Contains(out, "c2VjcmV0") {
		t.Errorf("credentials were printed:\n%s", out)
	}
}

func TestPreflightTokenInDotenvButNoLoginWarnsWithoutPrintingIt(t *testing.T) {
	cfg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg, "config.json"), []byte(`{"auths":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runWithFakes(t, "registry-preflight.sh", []string{"."}, "GHCR_TOKEN=ghp_notarealtoken\nDOCKER_CONFIG_DIR="+cfg+"\n", "", 0, "403")
	if code != 0 || !strings.Contains(out, "WARNING") || !strings.Contains(out, "no login for ghcr.io") || !strings.Contains(out, "GHCR_TOKEN configured here: yes") {
		t.Errorf("exit %d, output %s", code, out)
	}
	if strings.Contains(out, "ghp_notarealtoken") {
		t.Errorf("the token was printed:\n%s", out)
	}
}

func TestPreflightRegistryUnreachableSkips(t *testing.T) {
	out, code := runWithFakes(t, "registry-preflight.sh", []string{"."}, "", "", 0, "000")
	if code != 0 || strings.Contains(out, "WARNING") || !strings.Contains(out, "skipped") {
		t.Errorf("exit %d, output %s", code, out)
	}
}
