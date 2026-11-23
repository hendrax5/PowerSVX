package linux_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// node copies the generator scripts into a scratch repository root, because they
// derive their output and data directories from their own location.
func node(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the generators target Linux hosts")
	}
	root := t.TempDir()
	dst := filepath.Join(root, "deploy", "linux")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gen-unbound-conf.sh", "gen-dnsdist-conf.sh", "calc-mem-env.sh", "ensure-dnsdist-credentials.sh"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func sh(t *testing.T, root string, env []string, script string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(root, "deploy", "linux", script)}, args...)...)
	cmd.Env = append(os.Environ(), append([]string{"POWERSVX_DNS_DATAPLANE=dnsdist", "POWERSVX_ALLOW_DEFAULT_DNSDIST_CREDENTIALS=1"}, env...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func generate(t *testing.T, cpus, memMB string) (unbound, dnsdist string) {
	t.Helper()
	root := node(t)
	env := []string{"POWERSVX_HOST_CPUS=" + cpus, "POWERSVX_HOST_MEM_MB=" + memMB}
	ub := filepath.Join(root, "unbound.conf")
	dd := filepath.Join(root, "dnsdist.conf")
	if out, err := sh(t, root, env, "gen-unbound-conf.sh", ub); err != nil {
		t.Fatalf("gen-unbound-conf.sh: %v\n%s", err, out)
	}
	if out, err := sh(t, root, env, "gen-dnsdist-conf.sh", dd); err != nil {
		t.Fatalf("gen-dnsdist-conf.sh: %v\n%s", err, out)
	}
	ubText, err := os.ReadFile(ub)
	if err != nil {
		t.Fatal(err)
	}
	ddText, err := os.ReadFile(dd)
	if err != nil {
		t.Fatal(err)
	}
	return string(ubText), string(ddText)
}

func mustContain(t *testing.T, what, text string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("%s: expected %q", what, w)
		}
	}
}

func TestConfigIsSizedForTheRequestedNode(t *testing.T) {
	small := func(t *testing.T) {
		ub, dd := generate(t, "2", "2048")
		mustContain(t, "unbound for 2 CPUs / 2 GB", ub, "num-threads: 2\n", "msg-cache-size: 64m\n", "rrset-cache-size: 128m\n")
		mustContain(t, "dnsdist for 2 CPUs / 2 GB", dd, "newPacketCache(200000,", "sockets=8,")
	}
	large := func(t *testing.T) {
		ub, dd := generate(t, "12", "16384")
		mustContain(t, "unbound for 12 CPUs / 16 GB", ub, "num-threads: 6\n", "msg-cache-size: 327m\n", "rrset-cache-size: 655m\n")
		mustContain(t, "dnsdist for 12 CPUs / 16 GB", dd, "newPacketCache(1000000,", "sockets=24,")
	}
	t.Run("small", small)
	t.Run("large", large)
}

func TestMemoryLimitFollowsTheRequestedNodeSize(t *testing.T) {
	root := node(t)
	out, err := sh(t, root, []string{"POWERSVX_HOST_MEM_MB=2048"}, "calc-mem-env.sh")
	if err != nil {
		t.Fatalf("calc-mem-env.sh: %v\n%s", err, out)
	}
	// 30% of 2 GB in the dnsdist Dataplane, and 90% of that for the Go memory limit.
	mustContain(t, "memory env", out, "export POWERSVX_MEM_LIMIT=644245094\n", "export GOMEMLIMIT=579820584B\n")
}

func TestRejectsNonNumericSize(t *testing.T) {
	root := node(t)
	cases := []struct {
		script string
		env    string
	}{
		{"gen-unbound-conf.sh", "POWERSVX_HOST_CPUS=two"},
		{"gen-unbound-conf.sh", "POWERSVX_HOST_CPUS=0"},
		{"gen-unbound-conf.sh", "POWERSVX_HOST_MEM_MB=2G"},
		{"gen-dnsdist-conf.sh", "POWERSVX_HOST_CPUS=two"},
		{"gen-dnsdist-conf.sh", "POWERSVX_HOST_MEM_MB=2G"},
		{"calc-mem-env.sh", "POWERSVX_HOST_MEM_MB=2G"},
	}
	for _, tc := range cases {
		t.Run(tc.script+" "+tc.env, func(t *testing.T) {
			args := []string{}
			if tc.script != "calc-mem-env.sh" {
				args = append(args, filepath.Join(root, tc.script+".out"))
			}
			if out, err := sh(t, root, []string{tc.env}, tc.script, args...); err == nil {
				t.Fatalf("expected %s to refuse %s, it succeeded:\n%s", tc.script, tc.env, out)
			}
		})
	}
}

// Unbound only ever runs as the recursive backend behind dnsdist (ADR-0001): the
// generated configuration has no RPZ zones and never listens on the public port.
func TestUnboundConfigIsTheLoopbackBackendOnly(t *testing.T) {
	ub, _ := generate(t, "4", "4096")
	mustContain(t, "unbound backend", ub, "interface: 127.0.0.1\n", "port: 5353\n", "control-port: 8953\n")
	for _, banned := range []string{"rpz:", "zonefile:", "interface: 0.0.0.0", "port: 53\n", "mode=dataplane"} {
		if strings.Contains(ub, banned) {
			t.Errorf("generated Unbound configuration still contains %q:\n%s", banned, ub)
		}
	}
}

func TestUnboundGeneratorRefusesTheRemovedMode(t *testing.T) {
	root := node(t)
	for _, env := range []string{
		"POWERSVX_DNS_DATAPLANE=unbound",
		"POWERSVX_DNS_DATAPLANE=external",
		"POWERSVX_UNBOUND_MODE=dataplane",
	} {
		out, err := sh(t, root, []string{env}, "gen-unbound-conf.sh", filepath.Join(root, "unbound.conf"))
		if err == nil {
			t.Errorf("%s: expected the generator to refuse, it succeeded:\n%s", env, out)
		}
		if !strings.Contains(out, "was removed") {
			t.Errorf("%s: refusal does not say the mode was removed: %s", env, out)
		}
	}
}
