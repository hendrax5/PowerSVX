// Package dataplane holds the Dataplane black-box test: it starts the pinned
// dnsdist and Unbound in containers, configured by the generated configs, and
// asks real questions over every public transport.
//
// The test needs Docker, so it only runs when POWERSVX_DOCKER_TESTS=1.
//
//	POWERSVX_DOCKER_TESTS=1 go test -count=1 -timeout 10m ./test/dataplane/
//
// Optional: POWERSVX_DOCKER_TEST_HOST is the address the published ports are
// reachable on (default 127.0.0.1). Set it, for example to host.docker.internal,
// when `go test` itself runs inside a container that talks to the host's Docker.
package dataplane_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
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
	"github.com/quic-go/quic-go"
)

const (
	dnsdistImage = "powerdns/dnsdist-19:1.9.16" // keep in step with deploy/linux/docker-compose.host.yml
	unboundImage = "mvance/unbound:1.22.0"      // keep in step with deploy/linux/docker-compose.host.yml
	existingName = "exists.powersvx.test."
	existingAddr = "192.0.2.7"
	aRecords     = "server:\n    local-data: \"exists.powersvx.test. 60 IN A 192.0.2.7\"\n"
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
	return string(out)
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

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// hostPort returns the published host port of a container port such as "853/tcp".
func hostPort(t *testing.T, ctr, port string) string {
	t.Helper()
	line, _, _ := strings.Cut(docker(t, "port", ctr, port), "\n")
	_, p, err := net.SplitHostPort(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("docker port %s %s: %q: %v", ctr, port, line, err)
	}
	return p
}

type dataplane struct {
	udp53, tcp53, dot, doh, doq string
}

func startDataplane(t *testing.T, tuning ...string) *dataplane {
	t.Helper()
	root := repoRoot(t)
	work := t.TempDir()
	dot := string(filepath.Separator) + "."

	// Generate the configs exactly as a node does, in a scratch copy of the layout so
	// the generators write nothing into the repository.
	for _, f := range []string{"gen-dnsdist-conf.sh", "gen-unbound-conf.sh"} {
		copyFile(t, filepath.Join(root, "deploy", "linux", f), filepath.Join(work, "deploy", "linux", f))
	}
	genEnv := []string{
		"POWERSVX_DNS_DATAPLANE=dnsdist",
		"POWERSVX_DNSDIST_IPV6=0",
		"POWERSVX_ALLOW_DEFAULT_DNSDIST_CREDENTIALS=1",
		"POWERSVX_HOST_CPUS=2",
		"POWERSVX_HOST_MEM_MB=2048",
	}
	genEnv = append(genEnv, tuning...) // a later value wins over an earlier one
	run(t, work, genEnv, "sh", "deploy/linux/gen-dnsdist-conf.sh")
	if err := os.MkdirAll(filepath.Join(work, "configs", "unbound"), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, work, genEnv, "sh", "deploy/linux/gen-unbound-conf.sh")
	if len(tuning) > 0 {
		// A tuned run that silently fell back to the defaults would prove nothing.
		dd, _ := os.ReadFile(filepath.Join(work, "configs", "dnsdist", "dnsdist.conf"))
		ub, _ := os.ReadFile(filepath.Join(work, "configs", "unbound", "unbound.conf"))
		for _, want := range []string{"{reusePort=true})", "numberOfShards=4"} {
			if !strings.Contains(string(dd), want) {
				t.Fatalf("tuned dnsdist.conf lacks %q", want)
			}
		}
		for _, want := range []string{"num-threads: 4\n", "prefetch: yes\n"} {
			if !strings.Contains(string(ub), want) {
				t.Fatalf("tuned unbound.conf lacks %q", want)
			}
		}
	}

	// Throwaway test certificates.
	certs := filepath.Join(work, "certs")
	run(t, root, nil, "go", "run", "./cmd/gencert", certs)

	if err := os.WriteFile(filepath.Join(work, "a-records.conf"), []byte(aRecords), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "srv-records.conf"), []byte("# none\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	host, bind := "127.0.0.1", "127.0.0.1"
	if h := os.Getenv("POWERSVX_DOCKER_TEST_HOST"); h != "" {
		host, bind = h, "0.0.0.0"
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	dd := "powersvx-bb-dnsdist-" + suffix
	ub := "powersvx-bb-unbound-" + suffix
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("dnsdist log:\n%s", dockerQuiet("logs", "--tail", "60", dd))
			t.Logf("unbound log:\n%s", dockerQuiet("logs", "--tail", "60", ub))
		}
		_ = exec.Command("docker", "rm", "-f", "-v", ub).Run()
		_ = exec.Command("docker", "rm", "-f", "-v", dd).Run()
	})

	// dnsdist publishes the ports. Unbound joins its network namespace, so dnsdist
	// reaches it on 127.0.0.1:5353 exactly as in the host-networking deployment.
	create := []string{"create", "--name", dd, "--user", "0:0"}
	for _, p := range []string{"53/udp", "53/tcp", "853/tcp", "443/tcp", "784/udp"} {
		create = append(create, "-p", bind+"::"+p)
	}
	create = append(create, dnsdistImage, "--supervised", "--disable-syslog", "-C", "/etc/dnsdist/dnsdist.conf")
	docker(t, create...)
	docker(t, "cp", filepath.Join(work, "configs", "dnsdist", "dnsdist.conf"), dd+":/etc/dnsdist/dnsdist.conf")
	docker(t, "cp", filepath.Join(work, "data", "blocklist")+dot, dd+":/etc/dnsdist/blocklist")
	docker(t, "cp", certs+dot, dd+":/etc/dnsdist/certs")
	docker(t, "start", dd)

	docker(t, "create", "--name", ub, "--network", "container:"+dd, unboundImage)
	ubDir := ub + ":/opt/unbound/etc/unbound"
	docker(t, "cp", filepath.Join(work, "configs", "unbound", "unbound.conf"), ubDir+"/unbound.conf")
	docker(t, "cp", filepath.Join(work, "a-records.conf"), ubDir+"/a-records.conf")
	docker(t, "cp", filepath.Join(work, "srv-records.conf"), ubDir+"/srv-records.conf")
	docker(t, "cp", filepath.Join(work, "data", "unbound-rpz")+dot, ubDir+"/rpz")
	docker(t, "start", ub)

	return &dataplane{
		udp53: net.JoinHostPort(host, hostPort(t, dd, "53/udp")),
		tcp53: net.JoinHostPort(host, hostPort(t, dd, "53/tcp")),
		dot:   net.JoinHostPort(host, hostPort(t, dd, "853/tcp")),
		doh:   net.JoinHostPort(host, hostPort(t, dd, "443/tcp")),
		doq:   net.JoinHostPort(host, hostPort(t, dd, "784/udp")),
	}
}

func question(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	return m
}

var insecure = &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}

func classic(network string) func(string, *dns.Msg) (*dns.Msg, error) {
	return func(addr string, m *dns.Msg) (*dns.Msg, error) {
		c := &dns.Client{Net: network, Timeout: 3 * time.Second}
		r, _, err := c.Exchange(m, addr)
		return r, err
	}
}

func askDoT(addr string, m *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: insecure}
	r, _, err := c.Exchange(m, addr)
	return r, err
}

func askDoH(addr string, m *dns.Msg) (*dns.Msg, error) {
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: insecure, ForceAttemptHTTP2: true}}
	defer client.CloseIdleConnections()
	resp, err := client.Post("https://"+addr+"/dns-query", "application/dns-message", bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d: %s", resp.StatusCode, body)
	}
	out := new(dns.Msg)
	return out, out.Unpack(body)
}

func askDoQ(addr string, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0 // RFC 9250: the message ID is zero on DoQ
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conf := insecure.Clone()
	conf.NextProtos = []string{"doq"}
	conn, err := quic.DialAddr(ctx, addr, conf, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(wire)))
	if _, err := stream.Write(append(hdr[:], wire...)); err != nil {
		return nil, err
	}
	_ = stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	var n uint16
	if err := binary.Read(stream, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	return out, out.Unpack(buf)
}

// answer retries until the Dataplane returns a usable reply or the deadline passes.
func answer(ask func(string, *dns.Msg) (*dns.Msg, error), addr, name string, wait time.Duration) (*dns.Msg, error) {
	deadline := time.Now().Add(wait)
	for {
		r, err := ask(addr, question(name))
		if err == nil && r.Rcode != dns.RcodeServerFailure && r.Rcode != dns.RcodeRefused {
			return r, nil
		}
		if err == nil {
			err = fmt.Errorf("rcode %s", dns.RcodeToString[r.Rcode])
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(time.Second)
	}
}

func requireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("POWERSVX_DOCKER_TESTS") != "1" {
		t.Skip("set POWERSVX_DOCKER_TESTS=1 to run the Dataplane black-box test (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("POWERSVX_DOCKER_TESTS=1 but docker is not on PATH")
	}
}

func TestDataplaneAnswersOverEveryTransport(t *testing.T) {
	requireDocker(t)
	assertEveryTransportAnswers(t, startDataplane(t))
}

// Every tuning knob (ticket #18) on at once: the Dataplane must still answer over every
// transport. Four CPUs, so that "all" Unbound threads differs from "half" and the UDP
// listeners and cache shards are more than one.
func TestDataplaneAnswersOverEveryTransportWithEveryTuningKnobOn(t *testing.T) {
	requireDocker(t)
	dp := startDataplane(t,
		"POWERSVX_HOST_CPUS=4",
		"POWERSVX_DNSDIST_UDP_LISTENERS=auto",
		"POWERSVX_DNSDIST_CACHE_SHARDS=auto",
		"POWERSVX_UNBOUND_THREADS=all",
		"POWERSVX_UNBOUND_PREFETCH=yes")
	assertEveryTransportAnswers(t, dp)
}

func assertEveryTransportAnswers(t *testing.T, dp *dataplane) {
	t.Helper()
	transports := []struct {
		name string
		addr string
		ask  func(string, *dns.Msg) (*dns.Msg, error)
	}{
		{"udp", dp.udp53, classic("udp")},
		{"tcp", dp.tcp53, classic("tcp")},
		{"dot", dp.dot, askDoT},
		{"doh", dp.doh, askDoH},
		{"doq", dp.doq, askDoQ},
	}
	for i, tr := range transports {
		// The first transport waits for the containers to come up; the rest must answer at once.
		wait := 10 * time.Second
		if i == 0 {
			wait = 90 * time.Second
		}
		t.Run(tr.name, func(t *testing.T) {
			r, err := answer(tr.ask, tr.addr, existingName, wait)
			if err != nil {
				t.Fatalf("%s query for %s: %v", tr.name, existingName, err)
			}
			if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
				t.Fatalf("%s %s: rcode=%s answers=%v", tr.name, existingName, dns.RcodeToString[r.Rcode], r.Answer)
			}
			a, ok := r.Answer[0].(*dns.A)
			if !ok || a.A.String() != existingAddr {
				t.Fatalf("%s %s: want A %s, got %v", tr.name, existingName, existingAddr, r.Answer[0])
			}

			missing := fmt.Sprintf("nx-%s-%d.invalid.", tr.name, time.Now().UnixNano())
			r, err = answer(tr.ask, tr.addr, missing, wait)
			if err != nil {
				t.Fatalf("%s query for %s: %v", tr.name, missing, err)
			}
			if r.Rcode != dns.RcodeNameError {
				t.Fatalf("%s %s: want NXDOMAIN, got %s", tr.name, missing, dns.RcodeToString[r.Rcode])
			}
		})
	}
}
