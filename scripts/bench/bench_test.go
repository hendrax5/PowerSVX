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
	System    string  `json:"system"`
	Size      string  `json:"size"`
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
func benchmark(t *testing.T, capacity string, withRemote bool, extraEnv ...string) result {
	t.Helper()
	return readResult(t, benchmarkFile(t, capacity, withRemote, extraEnv, nil))
}

func readResult(t *testing.T, path string) result {
	t.Helper()
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

// benchmarkFile runs the harness against a pretend server and returns the path of the results file.
func benchmarkFile(t *testing.T, capacity string, withRemote bool, extraEnv, extraArgs []string) string {
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
	env = append(env, extraEnv...)
	if withRemote {
		env = append(env, "BENCH_REMOTE=bash "+filepath.Join(here, "testdata", "fake-remote.sh"))
	}
	if err := os.Chmod(filepath.Join(here, "testdata", "fake-dnsperf.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	args := []string{"-s", "127.0.0.1", "-p", port, "-d", queries, "-l", "unit",
		"-o", dir, "-t", "1", "-m", "2", "-T", "1"}
	out := run(t, env, "./run.sh", append(args, extraArgs...)...)
	return strings.TrimSpace(out)
}

func TestRecordsTheSystemItsSizeAndOnlyTheNamedContainers(t *testing.T) {
	requireBash(t)
	path := benchmarkFile(t, "5000", true, nil, []string{"-y", "technitium", "-Z", "small", "-R", "^unbound"})
	r := readResult(t, path)
	if r.System != "technitium" || r.Size != "small" {
		t.Fatalf("expected system technitium at small size, got %q at %q", r.System, r.Size)
	}
	if len(r.Server.MemoryUnderLoad) != 1 || !strings.HasPrefix(r.Server.MemoryUnderLoad[0], "unbound ") {
		t.Fatalf("expected memory for the unbound container only, got %v", r.Server.MemoryUnderLoad)
	}
	if len(r.Server.Images) != 0 {
		t.Fatalf("expected no images for containers outside the filter, got %v", r.Server.Images)
	}
}

func TestDefaultsToUnknownSystemAtFullSize(t *testing.T) {
	requireBash(t)
	r := benchmark(t, "5000", false)
	if r.System != "unknown" || r.Size != "full" {
		t.Fatalf("expected unknown system at full size, got %q at %q", r.System, r.Size)
	}
}

func TestRejectsAnInvalidSize(t *testing.T) {
	requireBash(t)
	if _, _, err := tryRun(nil, "./run.sh", "-s", "127.0.0.1", "-d", "testdata/popular.csv", "-l", "x", "-Z", "medium"); err == nil {
		t.Fatal("expected -Z medium to be refused")
	}
}

func requireJQ(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}
}

func compare(t *testing.T, a, b string) (string, error) {
	t.Helper()
	out, errOut, err := tryRun(nil, "./compare.sh", a, b)
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("compare.sh: %v\n%s", err, errOut)
		}
	}
	return out, err
}

func TestComparesTwoRunsOfTheSameKindSideBySide(t *testing.T) {
	requireBash(t)
	requireJQ(t)
	a := benchmarkFile(t, "5000", true, nil, []string{"-y", "powersvx"})
	b := benchmarkFile(t, "2500", true, nil, []string{"-y", "technitium"})
	out, err := compare(t, a, b)
	if err != nil {
		t.Fatalf("expected comparable runs to exit 0: %v\n%s", err, out)
	}
	for _, want := range []string{"COMPARABLE: yes", "powersvx", "technitium", "max qps:  A is", "memory:   A uses", "memory under load"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the comparison:\n%s", want, out)
		}
	}
}

func TestRefusesToCompareRunsOfDifferentSizes(t *testing.T) {
	requireBash(t)
	requireJQ(t)
	a := benchmarkFile(t, "5000", true, nil, []string{"-y", "powersvx"})
	b := benchmarkFile(t, "5000", true, nil, []string{"-y", "technitium", "-Z", "small"})
	out, err := compare(t, a, b)
	if err == nil {
		t.Fatalf("expected runs of different sizes to be reported as not comparable:\n%s", out)
	}
	for _, want := range []string{"COMPARABLE: no", "the sizes differ"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the comparison:\n%s", want, out)
		}
	}
}

func TestRefusesToCompareDifferentQuerySets(t *testing.T) {
	requireBash(t)
	requireJQ(t)
	a := benchmarkFile(t, "5000", true, nil, nil)
	raw, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	b := filepath.Join(t.TempDir(), "other.json")
	edited := strings.Replace(string(raw), `"sha256": "`, `"sha256": "0000`, 1)
	if edited == string(raw) {
		t.Fatal("could not edit the query set digest in the results file")
	}
	if err := os.WriteFile(b, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := compare(t, a, b)
	if err == nil || !strings.Contains(out, "the query sets differ") {
		t.Fatalf("expected different query sets to be reported as not comparable (err=%v):\n%s", err, out)
	}
}

func TestSaysWhenMemoryOrHardwareWasNotRecorded(t *testing.T) {
	requireBash(t)
	requireJQ(t)
	a := benchmarkFile(t, "5000", false, nil, nil)
	b := benchmarkFile(t, "5000", false, nil, nil)
	out, err := compare(t, a, b)
	if err != nil {
		t.Fatalf("expected runs with the same missing details to exit 0: %v\n%s", err, out)
	}
	for _, want := range []string{"memory was not recorded", "server hardware was not recorded"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the comparison:\n%s", want, out)
		}
	}
}

func TestCompareRejectsAFileThatIsNotAResult(t *testing.T) {
	requireBash(t)
	requireJQ(t)
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tryRun(nil, "./compare.sh", bad, bad); err == nil {
		t.Fatal("expected a file that is not a results file to be refused")
	}
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

func TestTreatsLateAnswersAsNotKeepingUp(t *testing.T) {
	requireBash(t)
	// Past its capacity this server loses nothing and answers everything late.
	r := benchmark(t, "5000", false, "FAKE_QUEUE=1")
	if r.LimitedBy != "server" {
		t.Fatalf("expected the server to be the limit when answers arrive late, got %q", r.LimitedBy)
	}
	if r.MaxQPS < 4500 || r.MaxQPS > 5000 {
		t.Fatalf("expected a maximum close to the server capacity of 5000 qps, got %.0f", r.MaxQPS)
	}
	if !r.Passed || r.Latency.P99 == nil || *r.Latency.P99 > 5 {
		t.Fatalf("expected the final measurement to stay within the latency limit, got passed=%v latency=%+v", r.Passed, r.Latency)
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
