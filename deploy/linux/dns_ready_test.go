package linux_test

import (
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// responder is a UDP DNS server that answers every query with one rcode,
// or stays silent, and records the names it was asked for.
type responder struct {
	port string

	mu    sync.Mutex
	names []string
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
			if silent {
				return
			}
			m := new(dns.Msg)
			m.SetRcode(q, rcode)
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return r
}

// ready runs the readiness check against the responder and reports whether it passed.
func ready(t *testing.T, r *responder, args ...string) bool {
	t.Helper()
	full := append([]string{"./dns-ready.sh", "-s", "127.0.0.1", "-p", r.port, "-t", "1"}, args...)
	out, err := exec.Command("bash", full...).CombinedOutput()
	if err == nil {
		return true
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("run dns-ready.sh: %v\n%s", err, out)
	}
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
	if ready(t, r, "example.com") {
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

func TestRetriesUntilTheWaitRunsOut(t *testing.T) {
	requireBash(t)
	r := startResponder(t, dns.RcodeSuccess, true)
	if ready(t, r, "-w", "2", "example.com") {
		t.Fatal("expected not ready after the wait runs out")
	}
	if got := r.asked(); len(got) < 2 {
		t.Fatalf("expected the check to retry while waiting, got %d queries", len(got))
	}
}
