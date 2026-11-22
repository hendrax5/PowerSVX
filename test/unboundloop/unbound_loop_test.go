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
	dns, api         string // host:port the published ports are reachable on
	dd, ub, cp       string // container names
	rpzInUnbound     string // path of the Control Plane's runtime zones file inside Unbound
	startControlPlane func()
}

// startStack brings up dnsdist and Unbound. The Control Plane is created but started by
// the caller, so the test can first prove that recursion works before it exists.
func startStack(t *testing.T) *stack {
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
	copyFile(t, filepath.Join(root, "configs", "powersvx.docker.host.toml"), filepath.Join(vol, "cfg", "powersvx.toml"), 0o644)

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

// resolves returns "" when name answers NOERROR with at least one A record, outside any hosted zone.
func resolves(addr, name string) string {
	r, err := ask(addr, name, dns.TypeA)
	if err != nil {
		return fmt.Sprintf("%s: %v", name, err)
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
		return fmt.Sprintf("%s: rcode %s with %d answers", name, rcodeName(r), len(r.Answer))
	}
	if r.Authoritative {
		return fmt.Sprintf("%s: answered authoritatively, not by recursion", name)
	}
	return ""
}

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

func TestDefaultConfigurationKeepsRecursionWorking(t *testing.T) {
	if os.Getenv("POWERSVX_DOCKER_TESTS") != "1" {
		t.Skip("set POWERSVX_DOCKER_TESTS=1 to run the Unbound loop regression test (needs Docker and the Internet)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("POWERSVX_DOCKER_TESTS=1 but docker is not on PATH")
	}
	s := startStack(t)

	// Before the Control Plane exists the Dataplane must already recurse; otherwise this
	// environment cannot tell a loop from having no Internet.
	if why := poll(120*time.Second, func() string { return resolves(s.dns, "example.net") }); why != "" {
		t.Fatalf("the Dataplane does not resolve a real name before the Control Plane starts (no Internet from Docker?): %s", why)
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

	t.Run("hosted name is answered authoritatively through dnsdist", func(t *testing.T) {
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
			t.Fatalf("%s: %s", hostedName, why)
		}
	})

	// Wait until Unbound itself reports the Control Plane's zone: its configuration was
	// written and Unbound reloaded it. Only then does the next assertion mean anything.
	if why := poll(60*time.Second, func() string {
		if out := unboundStubs(s); !strings.Contains(out, hostedZone) {
			return "unbound-control list_stubs: " + out
		}
		return ""
	}); why != "" {
		t.Fatalf("Unbound did not reload the Control Plane's configuration: %s", why)
	}

	t.Run("names outside the hosted zones still resolve by recursion", func(t *testing.T) {
		if fw := unboundForwards(s); strings.Contains(fw, "127.0.0.1") || strings.Contains(fw, "::1") {
			t.Errorf("Unbound forwards to a loopback address:\n%s", fw)
		}
		if why := resolves(s.dns, "example.org"); why != "" {
			t.Fatalf("recursion is broken after the Control Plane wrote its configuration: %s", why)
		}
		if why := freshLabel(s.dns, "example.com"); why != "" {
			t.Fatalf("recursion is broken after the Control Plane wrote its configuration: %s", why)
		}
	})

	// The console (or an old settings file) can still name Unbound's own address. The writer
	// must skip it, and say so, while recursion keeps working.
	t.Run("a forwarder pointing at Unbound itself is skipped and reported", func(t *testing.T) {
		mustAPI(t, s.api, "PUT", "/api/v1/settings", `{"resolver_mode":"forward","forwarders":["127.0.0.1:5353"]}`, http.StatusOK)
		if why := poll(30*time.Second, func() string {
			_, out := apiCall(t, s.api, "GET", "/api/v1/health", "")
			var h struct {
				Checks map[string]map[string]any `json:"checks"`
			}
			if err := json.Unmarshal([]byte(out), &h); err != nil {
				return err.Error()
			}
			if h.Checks["unbound_runtime"]["skipped_forwarders"] == nil {
				return "health has no skipped_forwarders: " + out
			}
			return ""
		}); why != "" {
			t.Fatal(why)
		}
		if fw := unboundForwards(s); strings.Contains(fw, "127.0.0.1") {
			t.Fatalf("Unbound was told to forward to itself:\n%s", fw)
		}
		if why := freshLabel(s.dns, "example.com"); why != "" {
			t.Fatalf("recursion is broken after a forwarder to Unbound was saved: %s", why)
		}
	})
}
