package bench_test

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func requireBash(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the benchmark harness targets Linux")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
}

// run executes a harness script and returns its stdout. It fails the test on a non-zero exit.
func run(t *testing.T, env []string, script string, args ...string) string {
	t.Helper()
	out, errOut, err := tryRun(env, script, args...)
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", script, args, err, errOut)
	}
	return out
}

func tryRun(env []string, script string, args ...string) (string, string, error) {
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func querySet(t *testing.T, args ...string) []string {
	t.Helper()
	base := []string{"-p", "testdata/popular.csv", "-f", "testdata/filter.txt"}
	out := run(t, nil, "./gen-queryset.sh", append(base, args...)...)
	return strings.Split(strings.TrimRight(out, "\n"), "\n")
}

func TestQuerySetIsRepeatable(t *testing.T) {
	requireBash(t)
	a := querySet(t, "-n", "2000", "-s", "7")
	b := querySet(t, "-n", "2000", "-s", "7")
	c := querySet(t, "-n", "2000", "-s", "8")
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatal("the same seed produced two different query sets")
	}
	if strings.Join(a, "\n") == strings.Join(c, "\n") {
		t.Fatal("different seeds produced the same query set")
	}
}

func TestQuerySetFollowsTheRequestedMix(t *testing.T) {
	requireBash(t)
	const total = 20000
	lines := querySet(t, "-n", "20000", "-F", "10", "-X", "20")
	if len(lines) != total {
		t.Fatalf("expected %d lines, got %d", total, len(lines))
	}
	popular := map[string]bool{"google.com": true, "youtube.com": true, "facebook.com": true, "wikipedia.org": true, "example.net": true}
	filter := map[string]bool{"bad-one.example": true, "bad-two.example": true}
	types := map[string]int{}
	names := map[string]int{}
	var nFilter, nMissing int
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("malformed line %q", line)
		}
		types[f[1]]++
		names[f[0]]++
		switch {
		case filter[f[0]]:
			nFilter++
		case strings.HasSuffix(f[0], ".psvxbench-nx"):
			nMissing++
		case !popular[f[0]]:
			t.Fatalf("name %q comes from none of the inputs", f[0])
		}
	}
	within := func(what string, got int, wantPct float64) {
		t.Helper()
		pct := 100 * float64(got) / total
		if pct < wantPct-2 || pct > wantPct+2 {
			t.Errorf("%s: expected about %.0f%%, got %.1f%%", what, wantPct, pct)
		}
	}
	within("Filter names", nFilter, 10)
	within("non-existent names", nMissing, 20)
	within("A queries", types["A"], 60)
	within("AAAA queries", types["AAAA"], 30)
	within("HTTPS queries", types["HTTPS"], 10)
	if names["google.com"] <= names["example.net"] {
		t.Errorf("expected the most popular name to be asked more often than the least popular (%d vs %d)",
			names["google.com"], names["example.net"])
	}
}

func TestQuerySetNeedsFilterNamesUnlessTheirShareIsZero(t *testing.T) {
	requireBash(t)
	if _, _, err := tryRun(nil, "./gen-queryset.sh", "-p", "testdata/popular.csv", "-n", "10"); err == nil {
		t.Fatal("expected an error when Filter names are wanted but no file is given")
	}
	out := run(t, nil, "./gen-queryset.sh", "-p", "testdata/popular.csv", "-n", "10", "-F", "0")
	if n := strings.Count(out, "\n"); n != 10 {
		t.Fatalf("expected 10 lines without a Filter file when its share is zero, got %d", n)
	}
}

func TestParsesRealDnsperfOutput(t *testing.T) {
	requireBash(t)
	out := run(t, nil, "./parse-dnsperf.sh", "testdata/dnsperf-2.14.txt")
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		k, v, _ := strings.Cut(line, "=")
		got[k] = v
	}
	want := map[string]string{
		"sent": "12", "completed": "12", "lost": "0", "loss_pct": "0.0000", "qps": "6.0",
		"latency_avg_ms": "2.862", "latency_p50_ms": "2.431", "latency_p95_ms": "4.223", "latency_p99_ms": "4.223",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: expected %s, got %q", k, v, got[k])
		}
	}
}

// startDNS answers every query with NXDOMAIN so the harness sees the server as ready.
func startDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	return port
}

type result struct {
	Label     string  `json:"label"`
	Passed    bool    `json:"passed"`
	MaxQPS    float64 `json:"max_qps"`
	LimitedBy string  `json:"limited_by"`
	LossPct   float64 `json:"loss_pct"`
	Latency   struct {
		P50 *float64 `json:"p50"`
		P99 *float64 `json:"p99"`
	} `json:"latency_ms"`
	Server struct {
		CPUs            *int     `json:"cpus"`
		MemTotalKB      *int     `json:"mem_total_kb"`
		Images          []string `json:"images"`
		MemoryUnderLoad []string `json:"memory_under_load"`
	} `json:"server"`
	QuerySet struct {
		Lines    int    `json:"lines"`
		Distinct int    `json:"distinct"`
		SHA256   string `json:"sha256"`
	} `json:"query_set"`
}

// benchmark runs the harness against a pretend server of the given capacity and returns the results file.
func benchmark(t *testing.T, capacity string, withRemote bool) result {
	t.Helper()
	port := startDNS(t)
	dir := t.TempDir()
	queries := filepath.Join(dir, "queries.txt")
	if err := os.WriteFile(queries, []byte("a.example A\nb.example AAAA\na.example A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	env := []string{
		"DNSPERF=" + filepath.Join(here, "testdata", "fake-dnsperf.sh"),
		"FAKE_CAPACITY=" + capacity,
		"FAKE_FLOOD=20000",
		"BENCH_PAUSE=0",
	}
	if withRemote {
		env = append(env, "BENCH_REMOTE=bash "+filepath.Join(here, "testdata", "fake-remote.sh"))
	}
	if err := os.Chmod(filepath.Join(here, "testdata", "fake-dnsperf.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := run(t, env, "./run.sh", "-s", "127.0.0.1", "-p", port, "-d", queries, "-l", "unit",
		"-o", dir, "-t", "1", "-m", "2", "-T", "1")
	path := strings.TrimSpace(out)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("results file %q: %v", path, err)
	}
	var r result
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("results file is not valid JSON: %v\n%s", err, raw)
	}
	return r
}

func TestFindsTheHighestRateTheServerKeepsUpWith(t *testing.T) {
	requireBash(t)
	r := benchmark(t, "5000", true)
	if !r.Passed {
		t.Fatalf("expected the final measurement to stay within the loss limit, loss was %.4f%%", r.LossPct)
	}
	if r.MaxQPS < 4500 || r.MaxQPS > 5000 {
		t.Fatalf("expected a maximum close to the server capacity of 5000 qps, got %.0f", r.MaxQPS)
	}
	if r.LimitedBy != "server" {
		t.Fatalf("expected the server to be the limit, got %q", r.LimitedBy)
	}
	if r.Latency.P50 == nil || r.Latency.P99 == nil || *r.Latency.P99 < *r.Latency.P50 {
		t.Fatalf("expected latency percentiles with p99 >= p50, got %+v", r.Latency)
	}
	if r.QuerySet.Lines != 3 || r.QuerySet.Distinct != 2 || len(r.QuerySet.SHA256) != 64 {
		t.Fatalf("expected the query set to be described, got %+v", r.QuerySet)
	}
}

func TestRecordsServerHardwareImagesAndMemory(t *testing.T) {
	requireBash(t)
	r := benchmark(t, "5000", true)
	if r.Server.CPUs == nil || *r.Server.CPUs != 8 || r.Server.MemTotalKB == nil || *r.Server.MemTotalKB != 16000000 {
		t.Fatalf("expected server hardware to be recorded, got %+v", r.Server)
	}
	if len(r.Server.Images) != 1 || len(r.Server.MemoryUnderLoad) != 2 {
		t.Fatalf("expected images and per-service memory, got %+v", r.Server)
	}
}

func TestSaysWhenTheLoadGeneratorIsTheLimit(t *testing.T) {
	requireBash(t)
	r := benchmark(t, "1000000", false)
	if r.LimitedBy != "load generator" {
		t.Fatalf("expected the load generator to be reported as the limit, got %q", r.LimitedBy)
	}
	if r.MaxQPS != 20000 {
		t.Fatalf("expected the maximum to be what the load generator could send (20000), got %.0f", r.MaxQPS)
	}
	if r.Server.CPUs != nil || len(r.Server.MemoryUnderLoad) != 0 {
		t.Fatalf("expected empty server details without a way to reach the server, got %+v", r.Server)
	}
}
