package dataplane_test

// The sampled query log, end to end: real dnsdist (generated configuration with
// POWERSVX_QUERY_LOG_DNSTAP=1) and real Unbound, the production dnstap decoder
// listening on a shared volume, and queries for every kind of Filter outcome.
//
//	POWERSVX_DOCKER_TESTS=1 go test -count=1 -timeout 10m -run QueryLog ./test/dataplane/
//
// POWERSVX_DNSTAP_CAPTURE=<dir> additionally saves what dnsdist sent (the raw
// Frame Streams bytes and one frame per Filter action) for the decoder's fixtures.

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/powersvx/powersvx/internal/blockcdb"
)

const (
	qlSinkImage = "alpine:3.20"
	qlAuthConf  = "server:\n    interface: 127.0.0.1\n    port: 5354\n    access-control: 127.0.0.0/8 allow\n    do-daemonize: no\n    use-syslog: no\n    verbosity: 1\n    local-zone: \"hosted.powersvx.test.\" static\n    local-data: \"www.hosted.powersvx.test. 60 IN A 192.0.2.9\"\n"

	qlAllowedName = "bank.allowed.powersvx.test."
	qlFilterName  = "blocked.filter.powersvx.test."
	qlCustomName  = "blocked.custom.powersvx.test."
	qlAuthName    = "www.hosted.powersvx.test."
	qlRecursed    = existingName
)

type sinkLine struct {
	Time     string `json:"time"`
	ClientIP string `json:"client_ip"`
	QName    string `json:"qname"`
	QType    string `json:"qtype"`
	RCode    string `json:"rcode"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	Frame    string `json:"frame_hex"`
}

type qlRig struct {
	dd, sink string
	udp53    string
}

// sinkLines returns the decoded queries the sink has printed so far.
func (r *qlRig) sinkLines(t *testing.T) []sinkLine {
	t.Helper()
	out, _ := exec.Command("docker", "logs", r.sink).Output()
	var lines []sinkLine
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var l sinkLine
		if json.Unmarshal(sc.Bytes(), &l) == nil && l.QName != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func (r *qlRig) setRate(t *testing.T, v string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "rate")
	if err := os.WriteFile(f, []byte(v+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	docker(t, "cp", f, r.sink+":/dnstap/rate")
}

func (r *qlRig) waitLog(t *testing.T, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(dockerQuiet("logs", r.dd), want) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("dnsdist never logged %q; log:\n%s", want, dockerQuiet("logs", "--tail", "40", r.dd))
}

func startQueryLogDataplane(t *testing.T) *qlRig {
	t.Helper()
	root := repoRoot(t)
	work := t.TempDir()
	dot := string(filepath.Separator) + "."

	for _, f := range []string{"gen-dnsdist-conf.sh", "gen-unbound-conf.sh"} {
		copyFile(t, filepath.Join(root, "deploy", "linux", f), filepath.Join(work, "deploy", "linux", f))
	}
	genEnv := []string{
		"POWERSVX_DNS_DATAPLANE=dnsdist",
		"POWERSVX_DNSDIST_IPV6=0",
		"POWERSVX_HOST_CPUS=2",
		"POWERSVX_HOST_MEM_MB=2048",
		"POWERSVX_QUERY_LOG_DNSTAP=1",
	}
	run(t, work, genEnv, "sh", "deploy/linux/gen-dnsdist-conf.sh")
	if err := os.MkdirAll(filepath.Join(work, "configs", "unbound"), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, work, genEnv, "sh", "deploy/linux/gen-unbound-conf.sh")

	// One name in each Filter store, written the way the Control Plane writes them.
	bl := filepath.Join(work, "data", "blocklist")
	for file, names := range map[string][]string{
		"domains.cdb":          {"filter.powersvx.test"},
		"custom_blacklist.cdb": {"custom.powersvx.test"},
		"whitelist.cdb":        {"allowed.powersvx.test"},
		"authzones.cdb":        {"hosted.powersvx.test"},
	} {
		if _, err := blockcdb.BuildCDB(filepath.Join(bl, file), names); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, "a-records.conf"), []byte(aRecords), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "srv-records.conf"), []byte("# none\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "auth.conf"), []byte(qlAuthConf), 0o644); err != nil {
		t.Fatal(err)
	}

	// The Control Plane's dnstap sink binary: static, copied into a small image.
	sinkBin := filepath.Join(work, "dnstapsink")
	cmd := exec.Command("go", "build", "-o", sinkBin, "./test/dataplane/dnstapsink")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build dnstapsink: %v\n%s", err, out)
	}

	host, bind := "127.0.0.1", "127.0.0.1"
	if h := os.Getenv("POWERSVX_DOCKER_TEST_HOST"); h != "" {
		host, bind = h, "0.0.0.0"
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	vol := "powersvx-ql-vol-" + suffix
	dd, ub, au, sink := "powersvx-ql-dnsdist-"+suffix, "powersvx-ql-unbound-"+suffix, "powersvx-ql-auth-"+suffix, "powersvx-ql-sink-"+suffix
	docker(t, "volume", "create", vol)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("dnsdist log:\n%s", dockerQuiet("logs", "--tail", "60", dd))
			t.Logf("sink log:\n%s", dockerQuiet("logs", "--tail", "3", sink))
		}
		for _, c := range []string{sink, au, ub, dd} {
			_ = exec.Command("docker", "rm", "-f", "-v", c).Run()
		}
		_ = exec.Command("docker", "volume", "rm", "-f", vol).Run()
	})

	// The sink owns the shared volume's contents (socket and rate file) just as the
	// Control Plane does in production, and dnsdist reads them.
	docker(t, "create", "--name", sink, "-v", vol+":/dnstap", "--entrypoint", "/dnstapsink", qlSinkImage, "/dnstap/query.sock", "/dnstap/stream.bin")
	docker(t, "cp", sinkBin, sink+":/dnstapsink")
	docker(t, "start", sink)

	create := []string{"create", "--name", dd, "--user", "0:0", "-v", vol + ":/etc/dnsdist/dnstap"}
	for _, p := range []string{"53/udp", "53/tcp"} {
		create = append(create, "-p", bind+"::"+p)
	}
	create = append(create, dnsdistImage, "--supervised", "--disable-syslog", "-C", "/etc/dnsdist/dnsdist.conf")
	docker(t, create...)
	docker(t, "cp", filepath.Join(work, "configs", "dnsdist", "dnsdist.conf"), dd+":/etc/dnsdist/dnsdist.conf")
	docker(t, "cp", filepath.Join(work, "data", "blocklist")+dot, dd+":/etc/dnsdist/blocklist")
	docker(t, "start", dd)

	docker(t, "create", "--name", ub, "--network", "container:"+dd, unboundImage)
	ubDir := ub + ":/opt/unbound/etc/unbound"
	docker(t, "cp", filepath.Join(work, "configs", "unbound", "unbound.conf"), ubDir+"/unbound.conf")
	docker(t, "cp", filepath.Join(work, "a-records.conf"), ubDir+"/a-records.conf")
	docker(t, "cp", filepath.Join(work, "srv-records.conf"), ubDir+"/srv-records.conf")
	docker(t, "cp", filepath.Join(work, "data", "unbound-rpz")+dot, ubDir+"/rpz")
	docker(t, "start", ub)

	// Stand-in for the Auth Backend on :5354.
	docker(t, "create", "--name", au, "--network", "container:"+dd, unboundImage)
	docker(t, "cp", filepath.Join(work, "auth.conf"), au+":/opt/unbound/etc/unbound/unbound.conf")
	docker(t, "start", au)

	return &qlRig{dd: dd, sink: sink, udp53: net.JoinHostPort(host, hostPort(t, dd, "53/udp"))}
}

func ask(addr, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	r, _, err := (&dns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(m, addr)
	return r, err
}

// waitEntries polls the sink until n entries for qname exist, and returns them.
func (r *qlRig) waitEntries(t *testing.T, qname string, n int) []sinkLine {
	t.Helper()
	want := strings.TrimSuffix(qname, ".")
	deadline := time.Now().Add(15 * time.Second)
	var got []sinkLine
	for time.Now().Before(deadline) {
		got = got[:0]
		for _, l := range r.sinkLines(t) {
			if l.QName == want {
				got = append(got, l)
			}
		}
		if len(got) >= n {
			return got
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("want %d logged queries for %s, got %d", n, want, len(got))
	return nil
}

func TestQueryLogSampling(t *testing.T) {
	if os.Getenv("POWERSVX_DOCKER_TESTS") != "1" {
		t.Skip("set POWERSVX_DOCKER_TESTS=1 to run the query log test (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("POWERSVX_DOCKER_TESTS=1 but docker is not on PATH")
	}
	rig := startQueryLogDataplane(t)

	// Wait until the Dataplane answers at all (sampling is still off: no rate file).
	if _, err := answer(classic("udp"), rig.udp53, existingName, 90*time.Second); err != nil {
		t.Fatalf("Dataplane did not come up: %v", err)
	}
	// The stand-in Auth Backend is marked up by dnsdist a few seconds after it starts.
	if _, err := answer(classic("udp"), rig.udp53, qlAuthName, 60*time.Second); err != nil {
		t.Fatalf("hosted zone not answered: %v", err)
	}

	t.Run("off by default: nothing arrives", func(t *testing.T) {
		for _, n := range []string{qlRecursed, qlFilterName, qlAuthName} {
			if _, err := ask(rig.udp53, n, dns.TypeA); err != nil {
				t.Fatalf("query %s: %v", n, err)
			}
		}
		time.Sleep(3 * time.Second)
		if got := rig.sinkLines(t); len(got) != 0 {
			t.Fatalf("sampling is off but %d queries were logged: %+v", len(got), got)
		}
		if strings.Contains(dockerQuiet("logs", rig.dd), "query log sampling at") {
			t.Fatal("dnsdist started sampling without a rate")
		}
		// The link to the Control Plane is up, though: that is how the console tells that
		// the Dataplane was generated with the sampled query log.
		if n := strings.TrimSpace(dockerQuiet("exec", rig.sink, "stat", "-c", "%s", "/dnstap/stream.bin")); n == "" || n == "0" {
			t.Fatalf("dnsdist did not connect to the listener (stream bytes %q)", n)
		}
	})

	rig.setRate(t, "1")
	rig.waitLog(t, "query log sampling at 1", 15*time.Second)

	t.Run("each Filter action is recorded", func(t *testing.T) {
		cases := []struct {
			name, action string
		}{
			{qlAllowedName, "allowed"},
			{qlFilterName, "blocked-filter"},
			{qlCustomName, "blocked-custom"},
			{qlAuthName, "auth"},
			{qlRecursed, "recursed"},
		}
		captured := map[string]string{}
		for _, c := range cases {
			r, err := ask(rig.udp53, c.name, dns.TypeA)
			if err != nil {
				t.Fatalf("query %s: %v", c.name, err)
			}
			if c.action == "blocked-filter" || c.action == "blocked-custom" {
				if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "139.255.196.196" {
					t.Fatalf("%s: expected the sinkhole answer, got %v", c.name, r.Answer)
				}
			}
			entries := rig.waitEntries(t, c.name, 1)
			e := entries[len(entries)-1]
			if e.Action != c.action {
				t.Errorf("%s: action %q, want %q (entry %+v)", c.name, e.Action, c.action, e)
			}
			if e.QType != "A" || e.Protocol != "udp" || e.ClientIP == "" {
				t.Errorf("%s: unexpected fields %+v", c.name, e)
			}
			captured[c.action] = e.Frame
		}

		// A repeat is answered from the packet cache: it must be logged as well.
		for i := 0; i < 2; i++ {
			if _, err := ask(rig.udp53, qlRecursed, dns.TypeA); err != nil {
				t.Fatal(err)
			}
		}
		rig.waitEntries(t, qlRecursed, 3)

		// The PTR cap answers REFUSED from dnsdist itself.
		refused := false
		for i := 0; i < 400 && !refused; i++ {
			r, err := ask(rig.udp53, "9.2.0.192.in-addr.arpa.", dns.TypePTR)
			refused = err == nil && r.Rcode == dns.RcodeRefused
		}
		if !refused {
			t.Fatal("could not trigger the PTR rate cap")
		}
		deadline := time.Now().Add(10 * time.Second)
		for ; time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
			for _, l := range rig.sinkLines(t) {
				if l.QType == "PTR" && l.Action == "refused" && l.RCode == "REFUSED" {
					captured["refused"] = l.Frame
				}
			}
			if captured["refused"] != "" {
				break
			}
		}
		if captured["refused"] == "" {
			t.Error("no refused PTR entry was logged")
		}

		if dir := os.Getenv("POWERSVX_DNSTAP_CAPTURE"); dir != "" {
			saveCapture(t, rig, dir, captured)
		}
	})

	t.Run("rate 0 removes the sampling again", func(t *testing.T) {
		rig.setRate(t, "0")
		rig.waitLog(t, "query log sampling off", 15*time.Second)
		before := len(rig.sinkLines(t))
		for i := 0; i < 5; i++ {
			_, _ = ask(rig.udp53, qlFilterName, dns.TypeA)
			_, _ = ask(rig.udp53, qlRecursed, dns.TypeA)
		}
		time.Sleep(3 * time.Second)
		if after := len(rig.sinkLines(t)); after != before {
			t.Fatalf("%d queries were logged after the rate was set to 0", after-before)
		}
	})
}

func saveCapture(t *testing.T, rig *qlRig, dir string, frames map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	docker(t, "cp", rig.sink+":/dnstap/stream.bin", filepath.Join(dir, "stream.bin"))
	var b strings.Builder
	for _, action := range []string{"allowed", "blocked-filter", "blocked-custom", "auth", "recursed", "refused"} {
		if f := frames[action]; f != "" {
			if _, err := hex.DecodeString(f); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&b, "%s %s\n", action, f)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "frames.txt"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The sampled query log is opt-in at generation time: a default node gets the same
// configuration as before the feature existed, with no rule or Lua call for it in the
// query path. This needs no Docker, only sh.
func TestDefaultDnsdistConfigHasNoQueryLogHook(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	root := repoRoot(t)
	generate := func(extra ...string) string {
		work := t.TempDir()
		copyFile(t, filepath.Join(root, "deploy", "linux", "gen-dnsdist-conf.sh"), filepath.Join(work, "deploy", "linux", "gen-dnsdist-conf.sh"))
		run(t, work, append([]string{"POWERSVX_DNSDIST_IPV6=0", "POWERSVX_HOST_CPUS=2", "POWERSVX_HOST_MEM_MB=2048"}, extra...), "sh", "deploy/linux/gen-dnsdist-conf.sh", "out.conf")
		b, err := os.ReadFile(filepath.Join(work, "out.conf"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	def := generate()
	for _, off := range []string{"POWERSVX_QUERY_LOG_DNSTAP=0", "POWERSVX_QUERY_LOG_DNSTAP="} {
		if got := generate(off); got != def {
			t.Fatalf("%s changes the generated configuration", off)
		}
	}
	for _, s := range []string{"dnstap", "Dnstap", "FrameStream", "ProbaRule", "ResponseAction", "querylog"} {
		if strings.Contains(def, s) {
			t.Errorf("default configuration mentions %q", s)
		}
	}
	on := generate("POWERSVX_QUERY_LOG_DNSTAP=1")
	if !strings.HasPrefix(on, strings.SplitAfter(def, "setSecurityPollSuffix(\"\")\n")[0]) || !strings.Contains(on, "DnstapLogResponseAction") {
		t.Fatal("opting in must add the hook after the Filter rules and leave them as they are")
	}
}
