package linux_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const goodUnboundConf = `server:
    port: 5353
    include: /opt/unbound/etc/unbound/rpz/runtime-server.conf

include: /opt/unbound/etc/unbound/rpz/runtime-zones.conf

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    control-use-cert: no
`

// fakeDocker records its arguments and answers like Docker when `start -a` runs
// unbound-checkconf: FAKE_RC is the exit status and FAKE_OUT what it prints.
const fakeDocker = `#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$1" in
  create) echo fakecid ;;
  start) [ -n "${FAKE_OUT:-}" ] && echo "$FAKE_OUT"; exit "${FAKE_RC:-0}" ;;
esac
exit 0
`

type checkRun struct {
	out    string
	code   int
	docker string // what the fake docker was asked to do
}

// runCheck lays out a checkout under a temp dir and runs check-unbound-conf.sh against it.
// A nil zones means no runtime-zones.conf file.
func runCheck(t *testing.T, conf string, zones *string, env ...string) checkRun {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	root := t.TempDir()
	for _, d := range []string{"configs/unbound", "data/unbound-rpz", "bin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("configs/unbound/unbound.conf", conf, 0o644)
	if zones != nil {
		write("data/unbound-rpz/runtime-zones.conf", *zones, 0o644)
	}
	write("bin/docker", fakeDocker, 0o755)
	log := filepath.Join(root, "docker.log")

	script, err := filepath.Abs("check-unbound-conf.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", script, root)
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + ":" + os.Getenv("PATH"), "FAKE_LOG=" + log}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(log)
	return checkRun{out: strings.ReplaceAll(string(out), root, "ROOT"), code: code, docker: strings.ReplaceAll(string(calls), root, "ROOT")}
}

func strp(s string) *string { return &s }

func TestCheckPassesAGoodConfiguration(t *testing.T) {
	r := runCheck(t, goodUnboundConf, strp("stub-zone:\n    name: \"a.test.\"\n    stub-addr: 127.0.0.1@5354\n\nforward-zone:\n    name: \".\"\n    forward-addr: 1.1.1.1@53\n"))
	if r.code != 0 {
		t.Fatalf("expected success, got %d:\n%s", r.code, r.out)
	}
	for _, want := range []string{"mvance/unbound:1.22.0", "cp ROOT/configs/unbound/unbound.conf fakecid:/opt/unbound/etc/unbound/unbound.conf", "fakecid:/opt/unbound/etc/unbound/rpz", "start -a fakecid", "rm -f -v fakecid"} {
		if !strings.Contains(r.docker, want) {
			t.Errorf("docker was not asked for %q; calls:\n%s", want, r.docker)
		}
	}
}

func TestCheckStopsWhenUnboundCheckconfRejectsTheConfiguration(t *testing.T) {
	r := runCheck(t, goodUnboundConf, strp("# empty\n"),
		"FAKE_RC=1", "FAKE_OUT=/opt/unbound/etc/unbound/rpz/runtime-zones.conf:4: error: unknown keyword bogus")
	if r.code == 0 {
		t.Fatalf("expected a failure:\n%s", r.out)
	}
	for _, want := range []string{"runtime-zones.conf:4", "not touching Unbound"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("output lacks %q:\n%s", want, r.out)
		}
	}
}

func TestCheckRefusesAForwardZoneToUnboundItself(t *testing.T) {
	loops := map[string]string{
		"unbound listener":      "forward-zone:\n    name: \".\"\n    forward-addr: 127.0.0.1@5353\n",
		"ipv6 loopback":         "forward-zone:\n    name: \".\"\n    forward-addr: ::1@5353\n",
		"no port means dnsdist": "forward-zone:\n    name: \".\"\n    forward-addr: 127.0.0.1\n",
		"dnsdist port":          "forward-zone:\n    name: \".\"\n    forward-addr: 127.0.0.1@53\n",
		"a named zone":          "forward-zone:\n    name: \"corp.local.\"\n    forward-addr: 10.0.0.1@53\n    forward-addr: 127.0.0.1@5353\n",
	}
	for name, zones := range loops {
		t.Run(name, func(t *testing.T) {
			r := runCheck(t, goodUnboundConf, strp(zones))
			if r.code == 0 {
				t.Fatalf("expected a refusal:\n%s", r.out)
			}
			if !strings.Contains(r.out, "ROOT/data/unbound-rpz/runtime-zones.conf") {
				t.Errorf("the refusal must name the file:\n%s", r.out)
			}
			if r.docker != "" {
				t.Errorf("a configuration that loops must stop before Docker is used:\n%s", r.docker)
			}
		})
	}
}

func TestCheckLetsAnotherResolverThrough(t *testing.T) {
	for name, zones := range map[string]string{
		"remote":                "forward-zone:\n    name: \".\"\n    forward-addr: 9.9.9.9@53\n    forward-addr: 2620:fe::fe\n",
		"loopback, other port":  "forward-zone:\n    name: \".\"\n    forward-addr: 127.0.0.1@5399\n",
		"commented out":         "# forward-addr: 127.0.0.1@5353\n",
		"not in a forward-zone": "stub-zone:\n    name: \"a.test.\"\n    stub-addr: 127.0.0.1@5354\n",
		"empty":                 "",
	} {
		t.Run(name, func(t *testing.T) {
			if r := runCheck(t, goodUnboundConf, strp(zones)); r.code != 0 {
				t.Fatalf("expected success:\n%s", r.out)
			}
		})
	}
}

func TestCheckHonoursTheConfiguredBackendPort(t *testing.T) {
	zones := strp("forward-zone:\n    name: \".\"\n    forward-addr: 127.0.0.1@5399\n")
	if r := runCheck(t, goodUnboundConf, zones, "POWERSVX_UNBOUND_BACKEND_PORT=5399"); r.code == 0 {
		t.Fatalf("5399 is the Unbound port here, expected a refusal:\n%s", r.out)
	}
}

func TestCheckRefusesADisabledControlInterface(t *testing.T) {
	conf := strings.Replace(goodUnboundConf, "control-enable: yes", "control-enable: no", 1)
	r := runCheck(t, conf, nil)
	if r.code == 0 || !strings.Contains(r.out, "ROOT/configs/unbound/unbound.conf") || !strings.Contains(r.out, "control interface") {
		t.Fatalf("expected a refusal naming unbound.conf (code %d):\n%s", r.code, r.out)
	}
	if r.docker != "" {
		t.Errorf("must stop before Docker is used:\n%s", r.docker)
	}
}

func TestCheckRefusesAConfigurationThatDoesNotLoadTheRuntimeFiles(t *testing.T) {
	conf := strings.Replace(goodUnboundConf, "include: /opt/unbound/etc/unbound/rpz/runtime-zones.conf\n", "", 1)
	if r := runCheck(t, conf, nil); r.code == 0 || !strings.Contains(r.out, "runtime-zones.conf") {
		t.Fatalf("expected a refusal (code %d):\n%s", r.code, r.out)
	}
}

func TestCheckRefusesAnEmptyConfiguration(t *testing.T) {
	if r := runCheck(t, "", nil); r.code == 0 {
		t.Fatalf("expected a refusal:\n%s", r.out)
	}
}

// The update and bootstrap scripts must run the check before they create or recreate Unbound.
func TestUpdateAndBootstrapCheckBeforeTouchingUnbound(t *testing.T) {
	for _, tc := range []struct{ script, touch string }{
		{"apply-update.sh", `up -d --no-deps --force-recreate unbound`},
		{"bootstrap-node.sh", `"${COMPOSE[@]}" up -d`},
	} {
		b, err := os.ReadFile(tc.script)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		check := strings.Index(s, "check-unbound-conf.sh")
		touch := strings.Index(s, tc.touch)
		if check < 0 || touch < 0 || check > touch {
			t.Errorf("%s: check-unbound-conf.sh (at %d) must run before %q (at %d)", tc.script, check, tc.touch, touch)
			continue
		}
		if !strings.Contains(s[check:], "|| exit 1") {
			t.Errorf("%s: a failed check must stop the script", tc.script)
		}
	}
}

func TestCheckUsesTheImageTheComposeFileRuns(t *testing.T) {
	compose, err := os.ReadFile("docker-compose.host.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`image:\s*(mvance/unbound:\S+)`).FindSubmatch(compose)
	if m == nil {
		t.Fatal("no Unbound image in docker-compose.host.yml")
	}
	script, _ := os.ReadFile("check-unbound-conf.sh")
	if !strings.Contains(string(script), `:-`+string(m[1])+`}"`) {
		t.Fatalf("check-unbound-conf.sh must default to %s", m[1])
	}
}

// A node that runs the sample unregenerated must still be reloadable by the Control Plane.
func TestSampleUnboundConfEnablesControlAndLoadsRuntimeFiles(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "configs", "unbound", "unbound.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"control-enable: yes", "control-interface: 127.0.0.1", "rpz/runtime-server.conf", "rpz/runtime-zones.conf"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("configs/unbound/unbound.conf lacks %q", want)
		}
	}
}
