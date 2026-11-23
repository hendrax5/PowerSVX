// Package dnssecdenial checks authenticated denial of existence from the Auth
// Backend with an independent validator: delv from ISC BIND, started in a
// container, is given the zone's own key as a trust anchor and asks the Auth
// Backend (the Server type, listening on a real UDP and TCP port) for a positive
// answer, an NXDOMAIN and a NODATA. Each must come back as fully validated.
//
// The test needs Docker, so it only runs when POWERSVX_DOCKER_TESTS=1.
//
//	POWERSVX_DOCKER_TESTS=1 go test -count=1 -timeout 10m ./test/dnssecdenial/
//
// The Auth Backend listens on the test process's host; the validator container
// reaches it as host.docker.internal (mapped to the host gateway). Set
// POWERSVX_DOCKER_TEST_HOST to the address the validator must use instead, for
// example the container's own IP when `go test` itself runs in a container.
package dnssecdenial_test

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/server"
)

const validatorImage = "internetsystemsconsortium/bind9:9.18" // delv 9.18

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

// listen starts the Auth Backend handler on one port, over UDP and TCP.
func listen(t *testing.T, srv *server.Server) int {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		tcp, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenPacket("udp", "0.0.0.0:"+strconv.Itoa(port))
		if err != nil {
			tcp.Close()
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

// startValidator starts a container that stays up so delv can be run in it many
// times; the trust anchor is written once.
func startValidator(t *testing.T, anchor string) string {
	t.Helper()
	name := fmt.Sprintf("powersvx-delv-%d", time.Now().UnixNano())
	docker(t, "", "run", "-d", "--rm", "--name", name,
		"--add-host", "host.docker.internal:host-gateway",
		"--entrypoint", "sleep", validatorImage, "3600")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	docker(t, anchor, "exec", "-i", name, "sh", "-c", "cat > /tmp/anchor.conf")
	return name
}

// trustAnchor renders the zone's key signing key as a delv trust anchor.
func trustAnchor(t *testing.T, s *dnssec.Signer) string {
	t.Helper()
	for _, rr := range s.DNSKEYs(zone) {
		k := rr.(*dns.DNSKEY)
		if k.Flags&dns.SEP != 0 {
			return fmt.Sprintf("trust-anchors {\n  \"%s\" static-key %d %d %d \"%s\";\n};\n", zone, k.Flags, k.Protocol, k.Algorithm, k.PublicKey)
		}
	}
	t.Fatal("no key signing key")
	return ""
}

func testHost() string {
	if h := os.Getenv("POWERSVX_DOCKER_TEST_HOST"); h != "" {
		return h
	}
	return "host.docker.internal"
}

// delv asks the Auth Backend through the validator and returns its output.
func delv(t *testing.T, container string, port int, tcp bool, name, qtype string) string {
	t.Helper()
	args := []string{"exec", container, "delv", "-a", "/tmp/anchor.conf", "-4",
		"@" + testHost(), "-p", strconv.Itoa(port), name, qtype, "+root=" + strings.TrimSuffix(zone, "."), "+multiline"}
	if tcp {
		args = append(args, "+tcp")
	} else {
		args = append(args, "+notcp")
	}
	var out bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run() // delv exits non-zero on a failed validation; the output says why
	return out.String()
}

type expectation struct {
	name, qtype string
	// substrings the validated output must contain
	want []string
}

func TestValidatorAuthenticatesPositiveNXDOMAINAndNODATAFromANSECSignedZone(t *testing.T) {
	if os.Getenv("POWERSVX_DOCKER_TESTS") != "1" {
		t.Skip("set POWERSVX_DOCKER_TESTS=1 to run the validator test (needs Docker)")
	}

	signer, srv := buildZone(t, dnssec.SignOptions{Algorithm: dns.ECDSAP256SHA256})
	port := listen(t, srv)
	container := startValidator(t, trustAnchor(t, signer))

	cases := []expectation{
		{"www.example.com.", "A", []string{"; fully validated", "192.0.2.10"}},
		{"www.example.com.", "TXT", []string{"; fully validated"}},
		{"missing.example.com.", "A", []string{"; negative response, fully validated", "nxdomain"}},
		{"x.www.example.com.", "A", []string{"; negative response, fully validated", "nxdomain"}},
		{"zz.example.com.", "A", []string{"; negative response, fully validated", "nxdomain"}},
		{"www.example.com.", "AAAA", []string{"; negative response, fully validated", "nxrrset"}},
		{"example.com.", "TXT", []string{"; negative response, fully validated", "nxrrset"}},
		{"z.example.com.", "A", []string{"; negative response, fully validated", "nxrrset"}},
		{"example.com.", "NSEC3PARAM", []string{"; negative response, fully validated", "nxrrset"}}, // an NSEC zone has none
		{"foo.w.example.com.", "AAAA", []string{"; negative response, fully validated", "nxrrset"}}, // wildcard NODATA
	}
	for _, tcp := range []bool{false, true} {
		proto := map[bool]string{false: "udp", true: "tcp"}[tcp]
		for _, c := range cases {
			c := c
			t.Run(proto+"/"+c.name+c.qtype, func(t *testing.T) {
				out := delv(t, container, port, tcp, c.name, c.qtype)
				t.Logf("delv %s %s (%s):\n%s", c.name, c.qtype, proto, out)
				for _, w := range c.want {
					if !strings.Contains(strings.ToLower(out), strings.ToLower(w)) {
						t.Errorf("output lacks %q", w)
					}
				}
				for _, bad := range []string{"unsigned answer", "insecurity proof failed", "resolution failed: SERVFAIL", "broken trust chain", "no valid signature", "RRSIG failed to verify"} {
					if strings.Contains(out, bad) {
						t.Errorf("output contains %q", bad)
					}
				}
			})
		}
	}
}

// buildZone loads the test zone into an Auth Backend and signs it with opts.
// z.example.com. is an empty non-terminal.
func buildZone(t *testing.T, opts dnssec.SignOptions) (*dnssec.Signer, *server.Server) {
	t.Helper()
	store := authoritative.NewStore()
	signer := dnssec.NewSigner(t.TempDir())
	store.UpsertZone(zone)
	add := func(name string, typ uint16, content string) {
		store.AddRecord(zone, authoritative.Record{Name: name, Type: typ, TTL: 300, Content: content})
	}
	add(zone, dns.TypeSOA, "ns1.example.com. hostmaster.example.com. 10 3600 600 86400 300")
	add(zone, dns.TypeNS, "ns1.example.com.")
	add("ns1.example.com.", dns.TypeA, "192.0.2.53")
	add("www.example.com.", dns.TypeA, "192.0.2.10")
	add("www.example.com.", dns.TypeTXT, "hello")
	add("b.example.com.", dns.TypeA, "192.0.2.11")
	add("a.z.example.com.", dns.TypeAAAA, "2001:db8::1")
	add("*.w.example.com.", dns.TypeA, "192.0.2.77") // wildcard with only an A record
	if err := signer.EnsureWithOptions(zone, opts); err != nil {
		t.Fatal(err)
	}
	srv := server.New(config.Default(), server.Deps{Auth: store, Signer: signer}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return signer, srv
}
