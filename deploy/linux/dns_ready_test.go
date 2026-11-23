package linux_test

import (
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// responder is a UDP DNS server that answers every query with one rcode,
// or stays silent, and records the names it was asked for.
type responder struct {
	port string

	mu    sync.Mutex
	names []string
	drop  int // the first drop queries get no answer
}

func (r *responder) asked() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.names...)
}

func startResponder(t *testing.T, rcode int, silent bool) *responder {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	r := &responder{port: port}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			if len(q.Question) > 0 {
				r.mu.Lock()
				r.names = append(r.names, q.Question[0].Name)
				r.mu.Unlock()
			}
			r.mu.Lock()
			dropped := r.drop > 0
			if dropped {
				r.drop--
			}
			r.mu.Unlock()
			if silent || dropped {
				return
			}
			m := new(dns.Msg)
			m.SetRcode(q, rcode)
			_ = w.WriteMsg(m)
		}),
	}
	serve(t, srv)
	return r
}

// serve starts srv and returns once it is reading, so no test starts the script early.
func serve(t *testing.T, srv *dns.Server) {
	t.Helper()
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the fake DNS server did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
}

// ready runs the readiness check against the responder and reports whether it passed.
func ready(t *testing.T, r *responder, args ...string) bool {
	t.Helper()
	full := append([]string{"./dns-ready.sh", "-s", "127.0.0.1", "-p", r.port, "-t", "5"}, args...)
	out, err := exec.Command("bash", full...).CombinedOutput()
	if err == nil {
		return true
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("run dns-ready.sh: %v\n%s", err, out)
	}
	t.Logf("dns-ready.sh %v: %v\nstderr: %s", args, err, out)
	return false
}

func requireBash(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("readiness check targets Linux hosts and containers")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
}

func TestReadyWhenServerAnswers(t *testing.T) {
	requireBash(t)
	cases := []struct {
		name  string
		rcode int
	}{
		{"name exists", dns.RcodeSuccess},
		{"name does not exist", dns.RcodeNameError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := startResponder(t, tc.rcode, false)
			if !ready(t, r, "example.com") {
				t.Fatalf("expected ready when the server answers with %s", dns.RcodeToString[tc.rcode])
			}
			if got := r.asked(); len(got) != 1 || got[0] != "example.com." {
				t.Fatalf("expected one query for example.com., got %v", got)
			}
		})
	}
}

func TestNotReadyWhenServerCannotResolve(t *testing.T) {
	requireBash(t)
	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			r := startResponder(t, rcode, false)
			if ready(t, r, "example.com") {
				t.Fatalf("expected not ready on %s", dns.RcodeToString[rcode])
			}
		})
	}
}

func TestNotReadyWhenServerIsSilent(t *testing.T) {
	requireBash(t)
	r := startResponder(t, dns.RcodeSuccess, true)
	if ready(t, r, "-t", "1", "example.com") {
		t.Fatal("expected not ready when no answer arrives")
	}
}

func TestUniqueNamesAvoidCachedAnswers(t *testing.T) {
	requireBash(t)
	r := startResponder(t, dns.RcodeNameError, false)
	if !ready(t, r, "-u", "invalid") || !ready(t, r, "-u", "invalid") {
		t.Fatal("expected ready on both runs")
	}
	got := r.asked()
	if len(got) != 2 {
		t.Fatalf("expected two queries, got %v", got)
	}
	if got[0] == got[1] {
		t.Fatalf("expected a different name on each run, got %q twice", got[0])
	}
	for _, n := range got {
		if !strings.HasSuffix(n, ".invalid.") || n == "invalid." {
			t.Fatalf("expected a fresh label under invalid., got %q", n)
		}
	}
}

// What -w promises: keep trying for at least the requested wait, and stop soon after it.
// The bounds are wide on purpose: a loaded machine can only make a probe slower, never shorter.
func TestRetriesUntilTheWaitRunsOut(t *testing.T) {
	requireBash(t)
	r := startResponder(t, dns.RcodeSuccess, true)
	const wait = 3 * time.Second
	start := time.Now()
	ok := ready(t, r, "-t", "1", "-w", "3", "example.com")
	elapsed := time.Since(start)
	if ok {
		t.Fatal("expected not ready after the wait runs out")
	}
	if elapsed < wait {
		t.Fatalf("gave up after %v, before the %v it was asked to wait", elapsed, wait)
	}
	if elapsed > wait+30*time.Second {
		t.Fatalf("kept trying for %v, far past the %v wait", elapsed, wait)
	}
	if len(r.asked()) < 1 {
		t.Fatal("the check never sent a query")
	}
}

// A server that misses the first queries and answers later: the check must retry and pass.
func TestRetryPassesOnceTheServerAnswers(t *testing.T) {
	requireBash(t)
	r := startResponder(t, dns.RcodeSuccess, false)
	r.drop = 2
	if !ready(t, r, "-t", "1", "-w", "60", "example.com") {
		t.Fatal("expected ready once the server started answering")
	}
	if got := r.asked(); len(got) < 3 {
		t.Fatalf("expected at least 3 queries (2 unanswered, then one answered), got %d", len(got))
	}
}

// startResolver models a resolver that answers .invalid by itself, as Unbound does, and
// resolves every other name only when recursion works. With recursion broken (a forward
// loop) it answers those with SERVFAIL, which is what the Dataplane did in ticket #40.
func startResolver(t *testing.T, recursionWorks bool) *responder {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	r := &responder{port: port}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			name := q.Question[0].Name
			r.mu.Lock()
			r.names = append(r.names, name)
			r.mu.Unlock()
			m := new(dns.Msg)
			switch {
			case strings.HasSuffix(name, ".invalid."):
				m.SetRcode(q, dns.RcodeNameError)
			case recursionWorks:
				m.SetRcode(q, dns.RcodeNameError) // a fresh label under a real domain does not exist
			default:
				m.SetRcode(q, dns.RcodeServerFailure)
			}
			_ = w.WriteMsg(m)
		}),
	}
	serve(t, srv)
	return r
}

func TestRecursionCheckFailsWhenRecursionIsBroken(t *testing.T) {
	requireBash(t)
	r := startResolver(t, false)
	if ready(t, r, "-r") {
		t.Fatal("expected not ready: the resolver cannot recurse")
	}
	// The local-name check cannot see this fault, which is why -r exists.
	if !ready(t, r, "-u", "invalid") {
		t.Fatal("a fresh .invalid name is answered locally, so it passes with recursion broken")
	}
}

func TestRecursionCheckPassesWhenRecursionWorks(t *testing.T) {
	requireBash(t)
	r := startResolver(t, true)
	if !ready(t, r, "-r") || !ready(t, r, "-r") {
		t.Fatal("expected ready on both runs while recursion works")
	}
	got := r.asked()
	if len(got) != 2 || got[0] == got[1] {
		t.Fatalf("expected two different fresh names, got %v", got)
	}
	for _, n := range got {
		if !strings.HasSuffix(n, ".example.com.") {
			t.Fatalf("expected a fresh label under the real name example.com., got %q", n)
		}
	}
}

func TestRecursionCheckUsesTheNameGiven(t *testing.T) {
	requireBash(t)
	r := startResolver(t, true)
	if !ready(t, r, "-r", "example.net") {
		t.Fatal("expected ready")
	}
	if got := r.asked(); len(got) != 1 || !strings.HasSuffix(got[0], ".example.net.") {
		t.Fatalf("got %v", got)
	}
}

func TestRecursionCheckRefusesNamesAnsweredLocally(t *testing.T) {
	requireBash(t)
	for _, name := range []string{"invalid", "ready.invalid", "test", "x.localhost", "corp.local", "1.0.0.127.in-addr.arpa"} {
		r := startResolver(t, true)
		cmd := exec.Command("bash", "./dns-ready.sh", "-s", "127.0.0.1", "-p", r.port, "-t", "5", "-r", name)
		out, err := cmd.CombinedOutput()
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 2 {
			t.Fatalf("-r %s: want exit 2, got err=%v\n%s", name, err, out)
		}
		if got := r.asked(); len(got) != 0 {
			t.Fatalf("-r %s must not send a query, sent %v", name, got)
		}
	}
}
