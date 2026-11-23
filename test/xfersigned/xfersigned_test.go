// Package xfersigned checks that a signed zone transferred out of the Auth
// Backend is served by a real secondary as a zone that validates. BIND (named
// 9.18, in a container) is the secondary: it pulls the zone by AXFR and, after the
// zone changes, by IXFR (which the Auth Backend answers with the whole signed
// zone). delv from the same image, given the primary's key signing key as the
// trust anchor, then validates what the secondary answers: a positive answer, an
// NXDOMAIN, a NODATA and answers made from wildcards, for an NSEC and an NSEC3
// zone, before and after the zone changes and after its signatures were renewed.
//
// The test needs Docker, so it only runs when POWERSVX_DOCKER_TESTS=1.
//
//	POWERSVX_DOCKER_TESTS=1 go test -count=1 -timeout 10m ./test/xfersigned/
//
// The Auth Backend listens on the test process's host; the container reaches it
// as host.docker.internal. Set POWERSVX_DOCKER_TEST_HOST to the address the
// container must use instead, for example when `go test` runs in a container.
package xfersigned_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/secondary"
	"github.com/powersvx/powersvx/internal/server"
)

const image = "internetsystemsconsortium/bind9:9.18"

const zone = "example.com."

func docker(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

// listen serves the Auth Backend handler on one port number, over UDP and TCP.
func listen(t *testing.T, srv *server.Server) int {
	t.Helper()
	for attempt := 0; attempt < 200; attempt++ {
		udp, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
		if err != nil {
			udp.Close()
			continue
		}
		h := dns.HandlerFunc(srv.ServeDNS)
		tcpSrv := &dns.Server{Listener: tcp, Handler: h}
		udpSrv := &dns.Server{PacketConn: udp, Handler: h}
		go tcpSrv.ActivateAndServe()
		go udpSrv.ActivateAndServe()
		t.Cleanup(func() { _ = tcpSrv.Shutdown(); _ = udpSrv.Shutdown() })
		return port
	}
	t.Fatal("no free port for the same UDP and TCP port number")
	return 0
}

func testHost() string {
	if h := os.Getenv("POWERSVX_DOCKER_TEST_HOST"); h != "" {
		return h
	}
	return "host.docker.internal"
}

type primary struct {
	store  *authoritative.Store
	signer *dnssec.Signer
	srv    *server.Server
	port   int
}

func (p *primary) add(name string, typ uint16, content string) {
	p.store.AddRecord(zone, authoritative.Record{Name: name, Type: typ, TTL: 300, Content: content})
}

// newPrimary hosts and signs the test zone and offers transfers of it. z.example.com.
// is an empty non-terminal.
func newPrimary(t *testing.T, opts dnssec.SignOptions) *primary {
	t.Helper()
	p := &primary{store: authoritative.NewStore(), signer: dnssec.NewSigner(t.TempDir())}
	p.store.UpsertZone(zone)
	p.add(zone, dns.TypeSOA, "ns1.example.com. hostmaster.example.com. 10 3600 600 86400 300")
	p.add(zone, dns.TypeNS, "ns1.example.com.")
	p.add("ns1.example.com.", dns.TypeA, "192.0.2.53")
	p.add("www.example.com.", dns.TypeA, "192.0.2.10")
	p.add("www.example.com.", dns.TypeTXT, "hello")
	p.add("b.example.com.", dns.TypeA, "192.0.2.11")
	p.add("a.z.example.com.", dns.TypeAAAA, "2001:db8::1")
	p.add("*.w.example.com.", dns.TypeA, "192.0.2.77")           // wildcard with only an A record
	p.add("*.c.example.com.", dns.TypeCNAME, "www.example.com.") // wildcard CNAME into the zone
	if err := p.signer.EnsureWithOptions(zone, opts); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Transfer.AllowAXFR = true
	cfg.Transfer.RequireTSIG = false
	p.srv = server.New(cfg, server.Deps{Auth: p.store, Signer: p.signer}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.port = listen(t, p.srv)
	return p
}

func (p *primary) trustAnchor(t *testing.T) string {
	t.Helper()
	for _, rr := range p.signer.DNSKEYs(zone) {
		k := rr.(*dns.DNSKEY)
		if k.Flags&dns.SEP != 0 {
			return fmt.Sprintf("trust-anchors {\n  \"%s\" static-key %d %d %d \"%s\";\n};\n", zone, k.Flags, k.Protocol, k.Algorithm, k.PublicKey)
		}
	}
	t.Fatal("no key signing key")
	return ""
}

// secondary is a BIND container holding example.com. as a secondary of the primary.
type target struct {
	name string
	host string // where delv asks, from inside the container
	port int
}

func exec1(t *testing.T, c string, args ...string) string {
	t.Helper()
	return docker(t, "", append([]string{"exec", c}, args...)...)
}

func startSecondary(t *testing.T, p *primary) *target {
	t.Helper()
	name := fmt.Sprintf("powersvx-bind-%d", time.Now().UnixNano())
	docker(t, "", "run", "-d", "--rm", "--name", name,
		"--add-host", "host.docker.internal:host-gateway",
		"--entrypoint", "sleep", image, "3600")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	host := testHost()
	if ip := net.ParseIP(host); ip == nil {
		out := strings.Fields(exec1(t, name, "getent", "ahostsv4", host))
		if len(out) == 0 {
			t.Fatalf("container cannot resolve %s", host)
		}
		host = out[0]
	}
	conf := fmt.Sprintf(`options {
  directory "/tmp";
  pid-file "/tmp/named.pid";
  listen-on port 53 { 127.0.0.1; };
  listen-on-v6 { none; };
  recursion no;
  dnssec-validation no;
  allow-query { any; };
  allow-transfer { none; };
  notify no;
};
key "rndc-key" { algorithm hmac-sha256; secret "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"; };
controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; }; };
zone "example.com" { type secondary; primaries { %s port %d; }; file "example.com.db"; };
`, host, p.port)
	docker(t, conf, "exec", "-i", name, "sh", "-c", "cat > /tmp/named.conf")
	docker(t, `key "rndc-key" { algorithm hmac-sha256; secret "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"; };`+"\n", "exec", "-i", name, "sh", "-c", "cat > /tmp/rndc.key")
	docker(t, p.trustAnchor(t), "exec", "-i", name, "sh", "-c", "cat > /tmp/anchor.conf")
	docker(t, "", "exec", "-d", name, "sh", "-c", "named -g -c /tmp/named.conf > /tmp/named.log 2>&1")
	s := &target{name: name, host: "127.0.0.1", port: 53}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "exec", name, "tail", "-n", "40", "/tmp/named.log").CombinedOutput()
			t.Logf("named log:\n%s", out)
		}
	})
	return s
}

// serial is the SOA serial the secondary answers with, 0 while it has no zone.
func (s *target) serial(t *testing.T) uint32 {
	t.Helper()
	out, _ := exec.Command("docker", "exec", s.name, "dig", "+short", "+tries=1", "+time=2", "@127.0.0.1", "example.com", "SOA").CombinedOutput()
	f := strings.Fields(string(out))
	if len(f) < 3 {
		return 0
	}
	n, _ := strconv.ParseUint(f[2], 10, 32)
	return uint32(n)
}

func (s *target) waitSerial(t *testing.T, want uint32) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var got uint32
	for time.Now().Before(deadline) {
		if got = s.serial(t); got == want {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("secondary serial is %d, want %d after 60s", got, want)
}

// refresh makes the secondary check its primary's SOA now and pull by IXFR.
func (s *target) refresh(t *testing.T) {
	t.Helper()
	exec1(t, s.name, "rndc", "-s", "127.0.0.1", "-p", "953", "-k", "/tmp/rndc.key", "-y", "rndc-key", "refresh", "example.com")
}

// delv asks the secondary through the validator.
func (s *target) delv(name, qtype string, tcp bool) string {
	args := []string{"exec", s.name, "delv", "-a", "/tmp/anchor.conf", "-4", "@" + s.host, "-p", strconv.Itoa(s.port),
		name, qtype, "+root=example.com", "+multiline"}
	if tcp {
		args = append(args, "+tcp")
	} else {
		args = append(args, "+notcp")
	}
	out, _ := exec.Command("docker", args...).CombinedOutput() // delv exits non-zero on a failed validation; the output says why
	return string(out)
}

type expectation struct {
	name, qtype string
	want        []string // substrings the validated output must contain
}

func (s *target) check(t *testing.T, cases []expectation) {
	t.Helper()
	for _, tcp := range []bool{false, true} {
		proto := map[bool]string{false: "udp", true: "tcp"}[tcp]
		for _, c := range cases {
			out := s.delv(c.name, c.qtype, tcp)
			for _, w := range c.want {
				if !strings.Contains(strings.ToLower(out), strings.ToLower(w)) {
					t.Errorf("delv %s %s (%s) output lacks %q:\n%s", c.name, c.qtype, proto, w, out)
				}
			}
			for _, bad := range []string{"unsigned answer", "insecurity proof failed", "resolution failed: SERVFAIL", "resolution failed: timed out", "broken trust chain", "no valid signature", "RRSIG failed to verify", "expired"} {
				if strings.Contains(out, bad) {
					t.Errorf("delv %s %s (%s) output contains %q:\n%s", c.name, c.qtype, proto, bad, out)
				}
			}
		}
	}
}

func skipWithoutDocker(t *testing.T) {
	if os.Getenv("POWERSVX_DOCKER_TESTS") != "1" {
		t.Skip("set POWERSVX_DOCKER_TESTS=1 to run the secondary test (needs Docker)")
	}
}

func firstCases(p *primary, nsec3 bool) []expectation {
	nsec3param := expectation{"example.com.", "NSEC3PARAM", []string{"; negative response, fully validated", "nxrrset"}}
	if nsec3 {
		pol, _ := p.signer.Policy(zone)
		nsec3param = expectation{"example.com.", "NSEC3PARAM", []string{"; fully validated", "NSEC3PARAM 1 0 1 " + pol.Salt}}
	}
	return []expectation{
		{"www.example.com.", "A", []string{"; fully validated", "192.0.2.10"}},
		{"www.example.com.", "TXT", []string{"; fully validated"}},
		{"example.com.", "DNSKEY", []string{"; fully validated"}},
		{"example.com.", "SOA", []string{"; fully validated"}},
		{"missing.example.com.", "A", []string{"; negative response, fully validated", "nxdomain"}},
		{"x.www.example.com.", "A", []string{"; negative response, fully validated", "nxdomain"}},
		{"zz.example.com.", "A", []string{"; negative response, fully validated", "nxdomain"}},
		{"www.example.com.", "AAAA", []string{"; negative response, fully validated", "nxrrset"}},
		{"example.com.", "TXT", []string{"; negative response, fully validated", "nxrrset"}},
		{"z.example.com.", "A", []string{"; negative response, fully validated", "nxrrset"}},
		nsec3param,
		{"foo.w.example.com.", "AAAA", []string{"; negative response, fully validated", "nxrrset"}},
		{"foo.w.example.com.", "A", []string{"; fully validated", "192.0.2.77", "RRSIG A 13 3 "}},
		{"a.b.w.example.com.", "A", []string{"; fully validated", "192.0.2.77", "RRSIG A 13 3 "}},
		{"x.c.example.com.", "A", []string{"; fully validated", "192.0.2.10"}},
		{"b.example.com.", "A", []string{"; fully validated", "192.0.2.11"}},
	}
}

var changedCases = []expectation{
	{"new.example.com.", "A", []string{"; fully validated", "192.0.2.99"}},
	{"b.example.com.", "A", []string{"; negative response, fully validated", "nxdomain"}},
	{"www.example.com.", "A", []string{"; fully validated", "192.0.2.10"}},
	{"missing.example.com.", "A", []string{"; negative response, fully validated", "nxdomain"}},
	{"foo.w.example.com.", "A", []string{"; fully validated", "192.0.2.77"}},
}

var renewedCases = []expectation{
	{"new.example.com.", "A", []string{"; fully validated", "192.0.2.99"}},
	{"example.com.", "DNSKEY", []string{"; fully validated"}},
	{"nothing.example.com.", "A", []string{"; negative response, fully validated", "nxdomain"}},
}

// changeZone adds one name and removes another.
func (p *primary) changeZone() uint32 {
	p.add("new.example.com.", dns.TypeA, "192.0.2.99")
	p.store.DeleteRecord(zone, "b.example.com.", dns.TypeA)
	return p.store.CurrentSOASerial(zone)
}

// renewSignatures makes the primary start a new signature refresh interval, which
// moves the serial with no record change.
func (p *primary) renewSignatures(t *testing.T) uint32 {
	t.Helper()
	if bumped := p.srv.RefreshSignedZones(time.Now().Add(8 * 24 * time.Hour)); len(bumped) != 1 {
		t.Fatalf("refresh bumped %v", bumped)
	}
	return p.store.CurrentSOASerial(zone)
}

func TestBINDSecondaryServesTheSignedZoneAndDelvValidatesIt(t *testing.T) {
	skipWithoutDocker(t)
	for _, nsec3 := range []bool{false, true} {
		name := map[bool]string{false: "nsec", true: "nsec3"}[nsec3]
		t.Run(name, func(t *testing.T) {
			p := newPrimary(t, dnssec.SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: nsec3})
			sec := startSecondary(t, p)
			sec.waitSerial(t, p.store.CurrentSOASerial(zone))
			t.Run("after the first transfer", func(t *testing.T) { sec.check(t, firstCases(p, nsec3)) })

			// The zone changes: the secondary asks for an IXFR and is sent the whole signed zone.
			want := p.changeZone()
			sec.refresh(t)
			sec.waitSerial(t, want)
			t.Run("after the zone changed", func(t *testing.T) { sec.check(t, changedCases) })

			// The signatures are renewed: the serial moves with no record change, and the
			// secondary still validates after pulling.
			want = p.renewSignatures(t)
			sec.refresh(t)
			sec.waitSerial(t, want)
			t.Run("after the signatures were renewed", func(t *testing.T) { sec.check(t, renewedCases) })
		})
	}
}

// startValidator starts a container that stays up so delv can be run in it many
// times against a server on the host.
func startValidator(t *testing.T, anchor string, port int) *target {
	t.Helper()
	name := fmt.Sprintf("powersvx-delv-%d", time.Now().UnixNano())
	docker(t, "", "run", "-d", "--rm", "--name", name,
		"--add-host", "host.docker.internal:host-gateway",
		"--entrypoint", "sleep", image, "3600")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	docker(t, anchor, "exec", "-i", name, "sh", "-c", "cat > /tmp/anchor.conf")
	return &target{name: name, host: testHost(), port: port}
}

// This software's own Secondary Zone pulls the signed zone from the primary, serves it
// on a real port without signing it (it holds keys of its own for the same zone name,
// which must stay unused: delv trusts only the primary's key), and keeps it valid
// across a record change and a signature renewal.
func TestOwnSecondaryZoneServesTheSignedZoneAndDelvValidatesIt(t *testing.T) {
	skipWithoutDocker(t)
	for _, nsec3 := range []bool{false, true} {
		name := map[bool]string{false: "nsec", true: "nsec3"}[nsec3]
		t.Run(name, func(t *testing.T) {
			p := newPrimary(t, dnssec.SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: nsec3})

			store := authoritative.NewStore()
			own := dnssec.NewSigner(t.TempDir())
			if err := own.Ensure(zone); err != nil {
				t.Fatal(err)
			}
			cfg := config.Default()
			srv := server.New(cfg, server.Deps{Auth: store, Signer: own}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			mgr := secondary.New(filepath.Join(t.TempDir(), "secondary-zones.json"), store, nil)
			srv.SetSecondary(mgr)
			if err := mgr.Upsert(secondary.Zone{Name: zone, Masters: []string{fmt.Sprintf("127.0.0.1:%d", p.port)}}); err != nil {
				t.Fatal(err)
			}
			pull := func(want uint32) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := mgr.Transfer(ctx, zone); err != nil {
					t.Fatal(err)
				}
				if got := store.CurrentSOASerial(zone); got != want {
					t.Fatalf("secondary serial %d, want %d", got, want)
				}
			}
			pull(p.store.CurrentSOASerial(zone))

			v := startValidator(t, p.trustAnchor(t), listen(t, srv))
			t.Run("after the first transfer", func(t *testing.T) { v.check(t, firstCases(p, nsec3)) })

			pull(p.changeZone())
			t.Run("after the zone changed", func(t *testing.T) { v.check(t, changedCases) })

			pull(p.renewSignatures(t))
			t.Run("after the signatures were renewed", func(t *testing.T) { v.check(t, renewedCases) })
		})
	}
}
