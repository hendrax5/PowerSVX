// Package unboundloop is the regression test for ticket #40: the default host
// configuration must not make Unbound forward every query to itself.
//
// It starts the pinned dnsdist and Unbound in containers, configured by the generated
// configs, and the real Control Plane built from this checkout and started with the
// shipped configs/powersvx.docker.host.toml. The three share one network namespace,
// like host networking. It creates a zone through the REST API, waits for the Control
// Plane to write Unbound's runtime configuration and for Unbound to reload it, then asks
// dnsdist for a hosted name (answered authoritatively) and for names outside every zone
// (answered by recursion).
//
// The test needs Docker and the Internet (recursion walks the real DNS), so it only runs
// when POWERSVX_DOCKER_TESTS=1.
//
//	POWERSVX_DOCKER_TESTS=1 go test -count=1 -timeout 10m ./test/unboundloop/
//
// POWERSVX_DOCKER_TEST_HOST is the address the published ports are reachable on
// (default 127.0.0.1); set it, for example to host.docker.internal, when `go test`
// itself runs inside a container that talks to the host's Docker.
//
// The Control Plane writes into the directory Unbound mounts, so that directory must be a
// real mount inside Unbound's chroot (a symlink to a path outside it makes `unbound-control
// reload` kill Unbound). The test shares one named volume between the containers and mounts
// sub-paths of it, which also works against a remote Docker daemon.
package unboundloop_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	dnsdistImage = "powerdns/dnsdist-19:1.9.16" // keep in step with deploy/linux/docker-compose.host.yml
	unboundImage = "mvance/unbound:1.22.0"      // keep in step with deploy/linux/docker-compose.host.yml
	cpImage      = "debian:bookworm-slim"
	apiToken     = "unbound-loop-test-token"
	adminPass    = "unbound-loop-test-throwaway"
	hostedZone   = "psvxloop.net"
	hostedName   = "www.psvxloop.net."
	hostedAddr   = "192.0.2.10"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, out.String(), errb.String())
	}
	return strings.TrimSpace(out.String())
}

func dockerQuiet(args ...string) string {
	out, _ := exec.Command("docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func run(t *testing.T, dir string, env []string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, mode); err != nil {
		t.Fatal(err)
	}
}

func hostPort(t *testing.T, ctr, port string) string {
	t.Helper()
	line, _, _ := strings.Cut(docker(t, "port", ctr, port), "\n")
	_, p, err := net.SplitHostPort(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("docker port %s %s: %q: %v", ctr, port, line, err)
	}
	return p
}

type stack struct {
	dns, api          string // host:port the published ports are reachable on
	dd, ub, cp        string // container names
	rpzInUnbound      string // path of the Control Plane's runtime zones file inside Unbound
	startControlPlane func()
}

// options vary what the Control Plane starts with. The zero value is the shipped default.
type options struct {
	toml     func(string) string // rewrites the shipped host configuration
	settings string              // content of data/runtime-settings.json saved by an earlier console session
	genEnv   []string            // extra environment for gen-dnsdist-conf.sh and gen-unbound-conf.sh
}

// startStack brings up dnsdist and Unbound. The Control Plane is created but started by
// the caller, so the test can first prove that recursion works before it exists.
func startStack(t *testing.T, o options) *stack {
	t.Helper()
	root := repoRoot(t)
	work := t.TempDir()
	dot := string(filepath.Separator) + "."

	// The Control Plane, built for the Docker host (Linux), from this checkout.
	bin := filepath.Join(work, "vol", "bin", "powersvx")
	build := exec.Command("go", "build", "-o", bin, "./cmd/powersvx")
	build.Dir = root
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/powersvx: %v\n%s", err, out)
	}

	// Generate the configs exactly as a node does, in a scratch copy of the layout.
	for _, f := range []string{"gen-dnsdist-conf.sh", "gen-unbound-conf.sh"} {
		copyFile(t, filepath.Join(root, "deploy", "linux", f), filepath.Join(work, "deploy", "linux", f), 0o755)
	}
	genEnv := []string{
		"POWERSVX_DNS_DATAPLANE=dnsdist",
		"POWERSVX_DNSDIST_IPV6=0",
		"POWERSVX_HOST_CPUS=2",
		"POWERSVX_HOST_MEM_MB=2048",
		"POWERSVX_CDB_REFRESH_SEC=3", // dnsdist picks up the zone CDB quickly
	}
	genEnv = append(genEnv, o.genEnv...)
	run(t, work, genEnv, "sh", "deploy/linux/gen-dnsdist-conf.sh")
	if err := os.MkdirAll(filepath.Join(work, "configs", "unbound"), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, work, genEnv, "sh", "deploy/linux/gen-unbound-conf.sh")

	// One volume, laid out like a node's data directory:
	//   blocklist/    dnsdist reads, the Control Plane writes (POWERSVX_BLOCKLIST_DIR)
	//   unbound-rpz/  Unbound mounts, the Control Plane writes (POWERSVX_UNBOUND_RPZ_DIR)
	//   data/         the Control Plane's data directory
	//   cfg/          the shipped host configuration, unchanged
	vol := filepath.Join(work, "vol")
	if err := os.Rename(filepath.Join(work, "data", "blocklist"), filepath.Join(vol, "blocklist")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(work, "data", "unbound-rpz"), filepath.Join(vol, "unbound-rpz")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(vol, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	toml, err := os.ReadFile(filepath.Join(root, "configs", "powersvx.docker.host.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if o.toml != nil {
		toml = []byte(o.toml(string(toml)))
	}
	if err := os.MkdirAll(filepath.Join(vol, "cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, "cfg", "powersvx.toml"), toml, 0o644); err != nil {
		t.Fatal(err)
	}
	if o.settings != "" {
		if err := os.WriteFile(filepath.Join(vol, "data", "runtime-settings.json"), []byte(o.settings), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	host, bind := "127.0.0.1", "127.0.0.1"
	if h := os.Getenv("POWERSVX_DOCKER_TEST_HOST"); h != "" {
		host, bind = h, "0.0.0.0"
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	s := &stack{
		dd:           "powersvx-ul-dnsdist-" + suffix,
		ub:           "powersvx-ul-unbound-" + suffix,
		cp:           "powersvx-ul-cp-" + suffix,
		rpzInUnbound: "/opt/unbound/etc/unbound/rpz/runtime-zones.conf",
	}
	volume := "powersvx-ul-vol-" + suffix
	loader := "powersvx-ul-load-" + suffix
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("dnsdist log:\n%s", dockerQuiet("logs", "--tail", "40", s.dd))
			t.Logf("unbound log:\n%s", dockerQuiet("logs", "--tail", "40", s.ub))
			t.Logf("control plane log:\n%s", dockerQuiet("logs", "--tail", "60", s.cp))
			t.Logf("runtime-zones.conf as Unbound sees it:\n%s", dockerQuiet("exec", s.ub, "cat", s.rpzInUnbound))
		}
		for _, c := range []string{s.cp, s.ub, s.dd, loader} {
			_ = exec.Command("docker", "rm", "-f", "-v", c).Run()
		}
		_ = exec.Command("docker", "volume", "rm", "-f", volume).Run()
	})

	docker(t, "volume", "create", volume)
	docker(t, "create", "--name", loader, "--mount", "type=volume,src="+volume+",dst=/vol", cpImage)
	docker(t, "cp", vol+dot, loader+":/vol")
	docker(t, "rm", "-f", "-v", loader)

	// dnsdist publishes the ports; Unbound and the Control Plane join its network
	// namespace, so dnsdist reaches Unbound on 127.0.0.1:5353 and the Control Plane
	// reaches Unbound's control interface on 127.0.0.1:8953, as on a host.
	docker(t, "create", "--name", s.dd, "--user", "0:0",
		"-p", bind+"::53/udp", "-p", bind+"::53/tcp", "-p", bind+"::5380/tcp",
		"--mount", "type=volume,src="+volume+",dst=/etc/dnsdist/blocklist,volume-subpath=blocklist,readonly",
		dnsdistImage, "--supervised", "--disable-syslog", "-C", "/etc/dnsdist/dnsdist.conf")
	docker(t, "cp", filepath.Join(work, "configs", "dnsdist", "dnsdist.conf"), s.dd+":/etc/dnsdist/dnsdist.conf")
	docker(t, "start", s.dd)

	// The runtime directory is a real mount inside Unbound's chroot, as in docker-compose.host.yml.
	docker(t, "create", "--name", s.ub, "--network", "container:"+s.dd,
		"--mount", "type=volume,src="+volume+",dst=/opt/unbound/etc/unbound/rpz,volume-subpath=unbound-rpz,readonly",
		unboundImage)
	docker(t, "cp", filepath.Join(work, "configs", "unbound", "unbound.conf"), s.ub+":/opt/unbound/etc/unbound/unbound.conf")
	docker(t, "start", s.ub)

	docker(t, "create", "--name", s.cp, "--network", "container:"+s.dd,
		"-e", "API_TOKEN="+apiToken, "-e", "ADMIN_PASSWORD="+adminPass,
		"-e", "POWERSVX_DATABASE_ENABLED=0", "-e", "POWERSVX_FILTER_SEED_URL=off",
		"-e", "POWERSVX_DNS_DATAPLANE=dnsdist", "-e", "POWERSVX_HOST_DEPLOYMENT=1",
		"-e", "POWERSVX_BLOCKLIST_DIR=/vol/blocklist", "-e", "POWERSVX_UNBOUND_RPZ_DIR=/vol/unbound-rpz",
		"--mount", "type=volume,src="+volume+",dst=/vol",
		cpImage, "/vol/bin/powersvx", "--config", "/vol/cfg/powersvx.toml", "--data-dir", "/vol/data")

	s.dns = net.JoinHostPort(host, hostPort(t, s.dd, "53/udp"))
	s.api = net.JoinHostPort(host, hostPort(t, s.dd, "5380/tcp"))
	s.startControlPlane = func() { docker(t, "start", s.cp) }
	return s
}

func question(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

func ask(addr, name string, qtype uint16) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: 8 * time.Second}
	r, _, err := c.Exchange(question(name, qtype), addr)
	return r, err
}

// poll retries f once a second until it returns "" (success) or the deadline passes.
func poll(wait time.Duration, f func() string) string {
	deadline := time.Now().Add(wait)
	for {
		last := f()
		if last == "" {
			return ""
		}
		if time.Now().After(deadline) {
			return last
		}
		time.Sleep(time.Second)
	}
}

func rcodeName(r *dns.Msg) string { return dns.RcodeToString[r.Rcode] }

// freshLabel returns "" when a fresh label under a real domain is answered NXDOMAIN or NOERROR
// (example.com answers every label): only a resolver that can recurse gets there, and the
// answer cannot come from a cache. SERVFAIL is what a forward loop gives.
func freshLabel(addr, domain string) string {
	name := fmt.Sprintf("loop-%d.%s", time.Now().UnixNano(), domain)
	r, err := ask(addr, name, dns.TypeA)
	if err != nil {
		return fmt.Sprintf("%s: %v", name, err)
	}
	if r.Rcode != dns.RcodeNameError && r.Rcode != dns.RcodeSuccess {
		return fmt.Sprintf("%s: want NXDOMAIN or NOERROR, got %s", name, rcodeName(r))
	}
	return ""
}

func apiCall(t *testing.T, addr, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func mustAPI(t *testing.T, addr, method, path, body string, want int) string {
	t.Helper()
	code, out := apiCall(t, addr, method, path, body)
	if code != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, code, want, out)
	}
	return out
}

// unboundStubs is what Unbound itself reports having loaded, read through its control
// interface: it lists the hosted zone only after the Control Plane's configuration was reloaded.
func unboundStubs(s *stack) string {
	return dockerQuiet("exec", s.ub, "/opt/unbound/sbin/unbound-control", "list_stubs")
}

func unboundForwards(s *stack) string {
	return dockerQuiet("exec", s.ub, "/opt/unbound/sbin/unbound-control", "list_forwards")
}

// freshUntilItWorks retries for a bounded time: after a reload the cache is cold, and the first
// lookups on a host without IPv6 can take several seconds (root priming, unreachable addresses).
// A loop never recovers, so it still fails, after the wait.
func freshUntilItWorks(addr string, wait time.Duration, domains ...string) string {
	return poll(wait, func() string {
		for _, d := range domains {
			if why := freshLabel(addr, d); why != "" {
				return why
			}
		}
		return ""
	})
}

// bringUp starts the stack, proves the Dataplane recurses before the Control Plane exists,
// starts the Control Plane, creates a zone through the REST API, and returns once dnsdist
// answers the hosted name and Unbound itself lists the zone (so the Control Plane
// configuration was written and reloaded).
func bringUp(t *testing.T, o options) *stack {
	t.Helper()
	if os.Getenv("POWERSVX_DOCKER_TESTS") != "1" {
		t.Skip("set POWERSVX_DOCKER_TESTS=1 to run the Unbound loop regression test (needs Docker and the Internet)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("POWERSVX_DOCKER_TESTS=1 but docker is not on PATH")
	}
	s := startStack(t, o)

	// Names nobody asked before: a fixed name can be answered from the Unbound cache while the
	// loop is loaded. Without Internet this cannot tell a loop from no recursion at all.
	if why := freshUntilItWorks(s.dns, 120*time.Second, "example.net"); why != "" {
		t.Fatalf("the Dataplane does not resolve a fresh name before the Control Plane starts (no Internet from Docker?): %s", why)
	}

	s.startControlPlane()
	if why := poll(90*time.Second, func() string {
		if code, out := apiCall(t, s.api, "GET", "/api/v1/health", ""); code != http.StatusOK {
			return fmt.Sprintf("health: %d %s", code, out)
		}
		return ""
	}); why != "" {
		t.Fatalf("the Control Plane did not come up: %s", why)
	}

	mustAPI(t, s.api, "POST", "/api/v1/zones", fmt.Sprintf(`{"name":%q}`, hostedZone), http.StatusCreated)
	mustAPI(t, s.api, "POST", "/api/v1/zones/"+hostedZone+"/records",
		fmt.Sprintf(`{"name":%q,"type":"A","content":%q,"ttl":300}`, "www."+hostedZone, hostedAddr), http.StatusCreated)

	if why := poll(60*time.Second, func() string {
		r, err := ask(s.dns, hostedName, dns.TypeA)
		if err != nil {
			return err.Error()
		}
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || !r.Authoritative {
			return fmt.Sprintf("rcode=%s aa=%v answers=%v", rcodeName(r), r.Authoritative, r.Answer)
		}
		if a, ok := r.Answer[0].(*dns.A); !ok || a.A.String() != hostedAddr {
			return fmt.Sprintf("answer=%v", r.Answer[0])
		}
		return ""
	}); why != "" {
		t.Fatalf("%s is not answered authoritatively through dnsdist: %s", hostedName, why)
	}
	if why := poll(60*time.Second, func() string {
		if out := unboundStubs(s); !strings.Contains(out, hostedZone) {
			return "unbound-control list_stubs: " + out
		}
		return ""
	}); why != "" {
		t.Fatalf("Unbound did not reload the Control Plane configuration: %s", why)
	}
	return s
}

func assertRecursion(t *testing.T, s *stack) {
	t.Helper()
	if fw := unboundForwards(s); strings.Contains(fw, "127.0.0.1") || strings.Contains(fw, "::1") {
		t.Errorf("Unbound forwards to a loopback address:\n%s", fw)
	}
	if why := freshUntilItWorks(s.dns, 60*time.Second, "example.com", "example.org"); why != "" {
		t.Fatalf("recursion is broken after the Control Plane wrote its configuration and Unbound reloaded: %s", why)
	}
}

func health(t *testing.T, s *stack) map[string]map[string]any {
	t.Helper()
	_, out := apiCall(t, s.api, "GET", "/api/v1/health", "")
	var h struct {
		Checks map[string]map[string]any `json:"checks"`
	}
	if err := json.Unmarshal([]byte(out), &h); err != nil {
		t.Fatalf("health: %v: %s", err, out)
	}
	return h.Checks
}

// The shipped default configuration, a zone created through the API: the hosted name is
// answered authoritatively and everything else still resolves by recursion.
func TestDefaultConfigurationKeepsRecursionWorking(t *testing.T) {
	s := bringUp(t, options{})
	assertRecursion(t, s)

	// The console used to offer a preset that saved the Unbound own address as the forwarder.
	t.Run("the API refuses a forwarder pointing at Unbound itself", func(t *testing.T) {
		code, out := apiCall(t, s.api, "PUT", "/api/v1/settings", `{"resolver_mode":"forward","forwarders":["127.0.0.1:5353"]}`)
		if code != http.StatusBadRequest || !strings.Contains(out, "Unbound would forward to itself") {
			t.Fatalf("want 400 with the reason, got %d %s", code, out)
		}
		assertRecursion(t, s)
	})
}

// The TOML is clean, but the console saved the old default earlier. The saved settings override
// the TOML, so this is the loop that a TOML fix never touches.
func TestSavedSettingsWithTheLoopDoNotBreakRecursion(t *testing.T) {
	s := bringUp(t, options{settings: `{"resolver_mode":"forward","forwarders":["127.0.0.1:5353"]}`})
	assertRecursion(t, s)

	saved := dockerQuiet("exec", s.cp, "cat", "/vol/data/runtime-settings.json")
	if strings.Contains(saved, "127.0.0.1") || !strings.Contains(saved, `"recursive"`) {
		t.Errorf("the saved settings must be rewritten at start without the loop:\n%s", saved)
	}
	if !strings.Contains(dockerQuiet("logs", s.cp), "removed those forwarders and rewrote the file") {
		t.Errorf("the rewrite must be logged")
	}
}

// A node still running the old shipped TOML (forward to 127.0.0.1:5353) and no saved settings:
// the writer must skip the loop, warn, and report it in the health output.
func TestOldShippedConfigurationIsGuardedAtRenderTime(t *testing.T) {
	s := bringUp(t, options{toml: func(toml string) string {
		toml = strings.ReplaceAll(toml, `mode = "recursive"`, `mode = "forward"`)
		return strings.ReplaceAll(toml, `forwarders = []`, `forwarders = ["127.0.0.1:5353"]`)
	}})
	assertRecursion(t, s)

	if why := poll(30*time.Second, func() string {
		if health(t, s)["unbound_runtime"]["skipped_forwarders"] == nil {
			return "health has no skipped_forwarders"
		}
		return ""
	}); why != "" {
		t.Fatal(why)
	}
	if !strings.Contains(dockerQuiet("logs", s.cp), "resolver forwarder skipped") {
		t.Errorf("the skip must be logged as a warning")
	}
}
