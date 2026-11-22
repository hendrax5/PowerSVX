package linux_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var (
	coreServices = []string{"dnsdist", "powersvx", "unbound", "watchtower"}
	obsServices  = []string{"grafana", "node-exporter", "postgres", "prometheus"}
)

// composeServices lists the services `docker compose config --services` selects for
// the given files, run from the repository root. It skips when Docker Compose is absent.
func composeServices(t *testing.T, files ...string) []string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("the docker compose plugin is not installed")
	}
	args := []string{"compose"}
	for _, f := range files {
		args = append(args, "-f", f)
	}
	args = append(args, "config", "--services")
	cmd := exec.Command("docker", args...)
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	got := strings.Fields(string(out))
	sort.Strings(got)
	return got
}

func sameServices(t *testing.T, what string, got, want []string) {
	t.Helper()
	want = append([]string(nil), want...)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("%s: got %v, want %v", what, got, want)
	}
}

func TestPlainComposeCommandStartsEveryService(t *testing.T) {
	all := append(append([]string{}, coreServices...), obsServices...)
	host := composeServices(t, "docker-compose.yml", "deploy/linux/docker-compose.host.yml")
	sameServices(t, "host networking, default selection", host, all)
}

func TestCoreOverlayLeavesOnlyTheCoreProfile(t *testing.T) {
	got := composeServices(t, "docker-compose.yml", "deploy/linux/docker-compose.host.yml", "deploy/linux/docker-compose.core.yml")
	sameServices(t, "host networking, core", got, coreServices)
}

// selectProfile runs select-profile.sh from a scratch repository root, with an optional .env.
func selectProfile(t *testing.T, dotenv string, env []string, args ...string) (stdout string, err error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the scripts target Linux hosts")
	}
	root := t.TempDir()
	dst := filepath.Join(root, "deploy", "linux")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("select-profile.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "select-profile.sh"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	if dotenv != "" {
		if err := os.WriteFile(filepath.Join(root, ".env"), []byte(dotenv), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", append([]string{filepath.Join(dst, "select-profile.sh")}, args...)...)
	cmd.Env = append(filterEnv(os.Environ(), "POWERSVX_PROFILE", "POWERSVX_HOST_MEM_MB"), env...)
	var out strings.Builder
	cmd.Stdout = &out
	err = cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func filterEnv(env []string, drop ...string) []string {
	var kept []string
next:
	for _, e := range env {
		for _, d := range drop {
			if strings.HasPrefix(e, d+"=") {
				continue next
			}
		}
		kept = append(kept, e)
	}
	return kept
}

func TestProfileSelection(t *testing.T) {
	cases := []struct {
		name   string
		dotenv string
		env    []string
		args   []string
		want   string
	}{
		{"2 GB host gets core", "", []string{"POWERSVX_HOST_MEM_MB=2048"}, nil, "core"},
		{"just under 4 GB gets core", "", []string{"POWERSVX_HOST_MEM_MB=4095"}, nil, "core"},
		{"4 GB host gets full", "", []string{"POWERSVX_HOST_MEM_MB=4096"}, nil, "full"},
		{"16 GB host gets full", "", []string{"POWERSVX_HOST_MEM_MB=16384"}, nil, "full"},
		{"explicit full wins on a small host", "", []string{"POWERSVX_PROFILE=full", "POWERSVX_HOST_MEM_MB=1024"}, nil, "full"},
		{"explicit core wins on a big host", "", []string{"POWERSVX_PROFILE=core", "POWERSVX_HOST_MEM_MB=32768"}, nil, "core"},
		{"setting in .env wins on a small host", "POWERSVX_PROFILE=full\n", []string{"POWERSVX_HOST_MEM_MB=1024"}, nil, "full"},
		{"environment beats .env", "POWERSVX_PROFILE=full\n", []string{"POWERSVX_PROFILE=core"}, nil, "core"},
		{"update path ignores memory", "", []string{"POWERSVX_HOST_MEM_MB=1024"}, []string{"-e"}, "full"},
		{"update path honours core", "POWERSVX_PROFILE=core\n", nil, []string{"-e"}, "core"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := selectProfile(t, c.dotenv, c.env, c.args...)
			if err != nil {
				t.Fatalf("select-profile.sh: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestProfileSelectionRejectsInvalidValues(t *testing.T) {
	for _, env := range [][]string{
		{"POWERSVX_PROFILE=minimal"},
		{"POWERSVX_PROFILE=CORE"},
		{"POWERSVX_HOST_MEM_MB=lots"},
	} {
		if got, err := selectProfile(t, "", env); err == nil {
			t.Errorf("%v: expected an error, got profile %q", env, got)
		}
	}
	if got, err := selectProfile(t, "POWERSVX_PROFILE=bogus\n", nil, "-e"); err == nil {
		t.Errorf("invalid value in .env: expected an error, got %q", got)
	}
}

func TestExplicitSettingIsReported(t *testing.T) {
	if _, err := selectProfile(t, "", []string{"POWERSVX_HOST_MEM_MB=1024"}, "-x"); err == nil {
		t.Error("-x succeeded although POWERSVX_PROFILE is not set")
	}
	if _, err := selectProfile(t, "", []string{"POWERSVX_PROFILE=core"}, "-x"); err != nil {
		t.Errorf("-x failed although POWERSVX_PROFILE is set: %v", err)
	}
	if _, err := selectProfile(t, "POWERSVX_PROFILE=core\n", nil, "-x"); err != nil {
		t.Errorf("-x failed although .env sets POWERSVX_PROFILE: %v", err)
	}
}
