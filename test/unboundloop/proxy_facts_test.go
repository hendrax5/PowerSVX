package unboundloop_test

// Facts about what the pinned dnsdist does to the queries it forwards to the Auth Backend,
// established against the real dnsdist and a probe that records the raw bytes it receives
// (test/unboundloop/probe). The results are quoted in docs/adr/0003-proxy-protocol-for-the-client-address.md.

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// generatedAuthLine is the Auth Backend entry exactly as gen-dnsdist-conf.sh writes it,
// read from the generated file so the test cannot drift from the generator.
func generatedAuthLine(t *testing.T, root string, env ...string) string {
	t.Helper()
	work := t.TempDir()
	copyFile(t, filepath.Join(root, "deploy", "linux", "gen-dnsdist-conf.sh"), filepath.Join(work, "deploy", "linux", "gen-dnsdist-conf.sh"), 0o755)
	run(t, work, append([]string{"POWERSVX_DNS_DATAPLANE=dnsdist", "POWERSVX_ALLOW_DEFAULT_DNSDIST_CREDENTIALS=1", "POWERSVX_DNSDIST_IPV6=0", "POWERSVX_HOST_CPUS=2", "POWERSVX_HOST_MEM_MB=2048"}, env...),
		"sh", "deploy/linux/gen-dnsdist-conf.sh")
	b, err := os.ReadFile(filepath.Join(work, "configs", "dnsdist", "dnsdist.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, `name="powersvx-auth"`) {
			return strings.TrimSpace(l)
		}
	}
	t.Fatal("no auth server line in the generated dnsdist configuration")
	return ""
}

type probeStack struct {
	dd, pr string
	seen   map[string][]string // what the probe received for each factStep title
	udp    string
	tcp    string
}

func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("POWERSVX_DOCKER_TESTS") != "1" {
		t.Skip("set POWERSVX_DOCKER_TESTS=1 to run the dnsdist facts test (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("POWERSVX_DOCKER_TESTS=1 but docker is not on PATH")
	}
}

// startProbe runs dnsdist with a minimal configuration (the given Auth Backend entry, then
// every query to the "auth" pool) and the probe in dnsdist's network namespace.
func startProbe(t *testing.T, authLine string, extra ...string) *probeStack {
	t.Helper()
	root := repoRoot(t)
	work := t.TempDir()
	bin := filepath.Join(work, "probe")
	build := exec.Command("go", "build", "-o", bin, "./test/unboundloop/probe")
	build.Dir = root
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build probe: %v\n%s", err, out)
	}
	conf := strings.Join(append([]string{
		`setLocal("0.0.0.0:53")`,
		`setACL({"0.0.0.0/0"})`,
		authLine,
	}, append(extra, `addAction(AllRule(), PoolAction("auth"))`)...), "\n") + "\n"
	confPath := filepath.Join(work, "dnsdist.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	host, bind := "127.0.0.1", "127.0.0.1"
	if h := os.Getenv("POWERSVX_DOCKER_TEST_HOST"); h != "" {
		host, bind = h, "0.0.0.0"
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	p := &probeStack{dd: "powersvx-pp-dnsdist-" + sfx, pr: "powersvx-pp-probe-" + sfx, seen: map[string][]string{}}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("dnsdist log:\n%s", dockerQuiet("logs", "--tail", "40", p.dd))
			t.Logf("probe log:\n%s", dockerQuiet("logs", p.pr))
		}
		for _, c := range []string{p.pr, p.dd} {
			_ = exec.Command("docker", "rm", "-f", "-v", c).Run()
		}
	})
	docker(t, "create", "--name", p.dd, "--user", "0:0", "-p", bind+"::53/udp", "-p", bind+"::53/tcp",
		dnsdistImage, "--supervised", "--disable-syslog", "-C", "/etc/dnsdist/dnsdist.conf")
	docker(t, "cp", confPath, p.dd+":/etc/dnsdist/dnsdist.conf")
	docker(t, "start", p.dd)
	docker(t, "create", "--name", p.pr, "--network", "container:"+p.dd, cpImage, "/probe", "127.0.0.1:5354")
	docker(t, "cp", bin, p.pr+":/probe")
	docker(t, "start", p.pr)
	p.udp = net.JoinHostPort(host, hostPort(t, p.dd, "53/udp"))
	p.tcp = net.JoinHostPort(host, hostPort(t, p.dd, "53/tcp"))
	// the probe is up when dnsdist gets answers through it
	if why := poll(60*time.Second, func() string {
		r, err := ask(p.udp, "up.psvx.test.", dns.TypeA)
		if err != nil {
			return err.Error()
		}
		if r.Rcode != dns.RcodeSuccess {
			return dns.RcodeToString[r.Rcode]
		}
		return ""
	}); why != "" {
		t.Fatalf("dnsdist does not forward to the probe: %s", why)
	}
	return p
}

// facts returns the probe's FACT lines.
func (p *probeStack) facts() []string {
	var out []string
	for _, l := range strings.Split(dockerQuiet("logs", p.pr), "\n") {
		if strings.HasPrefix(l, "FACT ") {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

func isHealth(l string) bool { return strings.Contains(l, "a.root-servers.net.") }

// since returns the FACT lines that are not in before, health checks left out.
func (p *probeStack) since(before []string) []string {
	seen := map[string]int{}
	for _, l := range before {
		seen[l]++
	}
	var out []string
	for _, l := range p.facts() {
		if seen[l] > 0 {
			seen[l]--
			continue
		}
		if isHealth(l) {
			continue
		}
		out = append(out, l)
	}
	return out
}

func exchange(netw, addr string, m *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: netw, Timeout: 6 * time.Second}
	r, _, err := c.Exchange(m, addr)
	return r, err
}

func withECS(m *dns.Msg, cidr string) *dns.Msg {
	ip, n, _ := net.ParseCIDR(cidr)
	ones, _ := n.Mask.Size()
	fam := uint16(1)
	a := ip.To4()
	if a == nil {
		fam, a = 2, ip.To16()
	}
	o := m.IsEdns0()
	if o == nil {
		m.SetEdns0(1232, false)
		o = m.IsEdns0()
	}
	o.Option = append(o.Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: fam, SourceNetmask: uint8(ones), Address: a})
	return m
}

func logFacts(t *testing.T, title string, lines []string) {
	t.Helper()
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString("  " + l + "\n")
	}
	t.Logf("%s\n%s", title, b.String())
}

// factStep runs f and returns what the probe received because of it.
func factStep(t *testing.T, p *probeStack, title string, f func()) []string {
	t.Helper()
	before := p.facts()
	f()
	time.Sleep(1500 * time.Millisecond)
	got := p.since(before)
	logFacts(t, title, got)
	p.seen[title] = got
	return got
}

func notify() *dns.Msg {
	m := new(dns.Msg)
	m.SetNotify("psvx.test.")
	return m
}

func update() *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate("psvx.test.")
	return m
}

// What dnsdist adds, replaces or leaves, for every kind of request, with the Auth Backend
// entry as the generator wrote it before PROXY protocol (useClientSubnet=true, no header).
func TestFactsWhatDnsdistForwardsToTheAuthBackend(t *testing.T) {
	needDocker(t)
	p := startProbe(t, generatedAuthLine(t, repoRoot(t), "POWERSVX_AUTH_PROXY_PROTOCOL=0"))
	step := func(title string, f func()) []string { return factStep(t, p, title, f) }

	step("UDP query without EDNS", func() { exchange("udp", p.udp, question("plain.psvx.test.", dns.TypeA)) })
	step("TCP query without EDNS", func() { exchange("tcp", p.tcp, question("plain-tcp.psvx.test.", dns.TypeA)) })
	step("UDP query with EDNS, no ECS", func() {
		m := question("edns.psvx.test.", dns.TypeA)
		m.SetEdns0(1232, true)
		exchange("udp", p.udp, m)
	})
	step("UDP query whose client sent ECS 203.0.113.0/24", func() {
		exchange("udp", p.udp, withECS(question("clientecs.psvx.test.", dns.TypeA), "203.0.113.0/24"))
	})
	step("TCP query whose client sent ECS 203.0.113.0/24", func() {
		exchange("tcp", p.tcp, withECS(question("clientecs-tcp.psvx.test.", dns.TypeA), "203.0.113.0/24"))
	})
	step("AXFR over TCP", func() { exchange("tcp", p.tcp, question("psvx.test.", dns.TypeAXFR)) })
	step("IXFR over TCP", func() { exchange("tcp", p.tcp, question("psvx.test.", dns.TypeIXFR)) })
	step("NOTIFY over UDP", func() { exchange("udp", p.udp, notify()) })
	step("UPDATE over UDP", func() { exchange("udp", p.udp, update()) })
	step("UPDATE over TCP", func() { exchange("tcp", p.tcp, update()) })
	var hc []string
	for _, l := range p.facts() {
		if isHealth(l) {
			hc = append(hc, l)
		}
	}
	if len(hc) > 3 {
		hc = hc[:3]
	}
	logFacts(t, "health checks seen by the backend (no PROXY configured)", hc)

	// What the ECS option dnsdist adds looks like, and what it does with the client's own.
	for _, title := range []string{"UDP query without EDNS", "TCP query without EDNS", "UDP query with EDNS, no ECS",
		"AXFR over TCP", "IXFR over TCP", "NOTIFY over UDP", "UPDATE over UDP", "UPDATE over TCP"} {
		p.need(t, title, "ECS(family=1 source=/24 scope=/0 addr=172.17.")
		p.needNot(t, title, "proxy=[PROXY")
	}
	p.need(t, "UDP query whose client sent ECS 203.0.113.0/24", "addr=203.0.113.0")
	p.needNot(t, "UDP query whose client sent ECS 203.0.113.0/24", "addr=172.17.")
	p.need(t, "TCP query whose client sent ECS 203.0.113.0/24", "addr=203.0.113.0")
	p.need(t, "NOTIFY over UDP", "opcode=NOTIFY")
	p.need(t, "UPDATE over TCP", "opcode=UPDATE")
}

// Which traffic carries the PROXY header, and what the health checks do.
func TestFactsProxyProtocolFromDnsdist(t *testing.T) {
	needDocker(t)
	line := generatedAuthLine(t, repoRoot(t), "POWERSVX_AUTH_PROXY_PROTOCOL=1")
	t.Logf("server line: %s", line)
	p := startProbe(t, line)
	step := func(title string, f func()) []string { return factStep(t, p, title, f) }

	step("UDP query", func() { exchange("udp", p.udp, question("plain.psvx.test.", dns.TypeA)) })
	step("TCP query", func() { exchange("tcp", p.tcp, question("plain-tcp.psvx.test.", dns.TypeA)) })
	step("TCP, two queries on one client connection", func() {
		c, err := dns.DialTimeout("tcp", p.tcp, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for i := 0; i < 2; i++ {
			_ = c.WriteMsg(question(fmt.Sprintf("keep%d.psvx.test.", i), dns.TypeA))
			_, _ = c.ReadMsg()
		}
	})
	step("AXFR over TCP", func() { exchange("tcp", p.tcp, question("psvx.test.", dns.TypeAXFR)) })
	step("NOTIFY over UDP", func() { exchange("udp", p.udp, notify()) })
	step("UPDATE over UDP", func() { exchange("udp", p.udp, update()) })
	time.Sleep(12 * time.Second)
	var hc []string
	for _, l := range p.facts() {
		if isHealth(l) {
			hc = append(hc, l)
		}
	}
	if len(hc) > 4 {
		hc = hc[:4]
	}
	logFacts(t, "health checks seen by the backend (useProxyProtocol=true)", hc)

	// The header: version 2, UDP and TCP, every kind of request, LOCAL for dnsdist's own checks.
	p.need(t, "UDP query", "proxy=[PROXY transport=2 src=172.17.0.1:")
	p.need(t, "TCP query", "proxy=[PROXY transport=1 src=172.17.0.1:")
	for _, title := range []string{"AXFR over TCP", "NOTIFY over UDP", "UPDATE over UDP"} {
		p.need(t, title, "proxy=[PROXY transport=")
		p.needNot(t, title, "proxy=[none]")
	}
	p.need(t, "NOTIFY over UDP", "opcode=NOTIFY")
	p.need(t, "UPDATE over UDP", "opcode=UPDATE")
	// One backend connection per client connection, one header at its start.
	two := strings.Join(p.seen["TCP, two queries on one client connection"], "\n")
	if strings.Count(two, "opened") != 1 || strings.Count(two, "opcode=QUERY") != 2 {
		t.Errorf("two queries on one client connection must use one backend connection with one header:\n%s", two)
	}
	if len(hc) == 0 {
		t.Fatal("the health checks did not reach the backend")
	}
	for _, l := range hc {
		if !strings.Contains(l, "proxy=[LOCAL]") {
			t.Errorf("a health check must carry a LOCAL header: %s", l)
		}
	}
}

// A request that carries a TSIG signature, and a query that carries the client's own ECS,
// through each way of configuring the Auth Backend entry.
func TestFactsSignedAndClientECSRequests(t *testing.T) {
	needDocker(t)
	secret := "c2VjcmV0LWZvci10aGUtZmFjdHMtdGVzdA==" // base64 of a throwaway string
	sign := func(m *dns.Msg) *dns.Msg { m.SetTsig("key.", dns.HmacSHA256, 300, time.Now().Unix()); return m }
	for _, proxy := range []string{"0", "1"} {
		t.Run("generated with POWERSVX_AUTH_PROXY_PROTOCOL="+proxy, func(t *testing.T) {
			line := generatedAuthLine(t, repoRoot(t), "POWERSVX_AUTH_PROXY_PROTOCOL="+proxy)
			t.Logf("server line: %s", line)
			p := startProbe(t, line)
			factStep(t, p, "TSIG-signed NOTIFY over UDP", func() {
				c := &dns.Client{Net: "udp", Timeout: 6 * time.Second, TsigSecret: map[string]string{"key.": secret}}
				_, _, _ = c.Exchange(sign(notify()), p.udp)
			})
			factStep(t, p, "TSIG-signed AXFR request over TCP", func() {
				conn, err := dns.DialTimeout("tcp", p.tcp, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				tr := &dns.Transfer{Conn: conn, TsigSecret: map[string]string{"key.": secret}, ReadTimeout: 3 * time.Second}
				if ch, err := tr.In(sign(question("psvx.test.", dns.TypeAXFR)), p.tcp); err == nil {
					for range ch {
					}
				}
			})
			factStep(t, p, "query whose client sent ECS 203.0.113.0/24 (UDP)", func() {
				exchange("udp", p.udp, withECS(question("clientecs.psvx.test.", dns.TypeA), "203.0.113.0/24"))
			})
			if proxy == "0" {
				// dnsdist appends its OPT record after the TSIG record: the signed message is changed
				// and the TSIG is no longer the last record, so it cannot be verified.
				p.need(t, "TSIG-signed NOTIFY over UDP", "tsig=false", "additional=[TSIG,OPT]")
				p.need(t, "TSIG-signed AXFR request over TCP", "tsig=false", "additional=[TSIG,OPT]")
			} else {
				p.need(t, "TSIG-signed NOTIFY over UDP", "tsig=true", "additional=[TSIG]")
				p.need(t, "TSIG-signed AXFR request over TCP", "tsig=true", "additional=[TSIG]")
			}
			// dnsdist keeps the ECS option a client sent; it does not replace it.
			p.need(t, "query whose client sent ECS 203.0.113.0/24 (UDP)", "addr=203.0.113.0")
		})
	}
}

// dnsdist's packet cache in front of the Auth Backend (the "auth" pool). With PROXY protocol
// the client address is not part of the request bytes. Does the cache key still separate two
// clients that share an ECS prefix?
func TestFactsPacketCacheInFrontOfTheAuthBackend(t *testing.T) {
	needDocker(t)
	root := repoRoot(t)
	dnsq := buildTool(t, "dnsq")
	for _, proxy := range []string{"0", "1"} {
		t.Run("proxy="+proxy, func(t *testing.T) {
			p := startProbe(t, generatedAuthLine(t, root, "POWERSVX_AUTH_PROXY_PROTOCOL="+proxy),
				`pcAuth = newPacketCache(1000,{maxTTL=300, minTTL=0, maxNegativeTTL=60})`,
				`getPool("auth"):setCache(pcAuth)`)
			a, b := startClient(t, dnsq), startClient(t, dnsq)
			dd := dnsdistAddr(t, p.dd)
			t.Logf("client A %s, client B %s (same /24)", a.ip, b.ip)
			got := factStep(t, p, "the same name asked by A, then B", func() {
				a.ask(dd, "-n", "cache.psvx.test.", "-t", "A")
				time.Sleep(300 * time.Millisecond)
				b.ask(dd, "-n", "cache.psvx.test.", "-t", "A")
			})
			t.Logf("the backend received %d request(s) for 2 queries from 2 clients", len(got))
			// The key is the query bytes (ECS included), not the PROXY header: client B is answered from
			// the entry A created. This is why the generated configuration has no cache in front of the
			// Auth Backend.
			if len(got) != 1 && !strings.Contains(strings.Join(got, ""), "opened") {
				t.Errorf("the second client was not answered from the cache: the backend saw %d requests", len(got))
			}
		})
	}
}

// need fails unless the lines the probe received for title contain every substring.
func (p *probeStack) need(t *testing.T, title string, subs ...string) {
	t.Helper()
	all := strings.Join(p.seen[title], "\n")
	if all == "" {
		t.Fatalf("%s: the backend received nothing", title)
	}
	for _, s := range subs {
		if !strings.Contains(all, s) {
			t.Errorf("%s: want %q in what the backend received:\n%s", title, s, all)
		}
	}
}

func (p *probeStack) needNot(t *testing.T, title string, subs ...string) {
	t.Helper()
	all := strings.Join(p.seen[title], "\n")
	for _, s := range subs {
		if strings.Contains(all, s) {
			t.Errorf("%s: did not expect %q in what the backend received:\n%s", title, s, all)
		}
	}
}
