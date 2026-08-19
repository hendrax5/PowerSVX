package upstream

import (
	"testing"
	"time"
)

func newServer(addr string, up bool, ewmaNs uint64) *Server {
	s := &Server{Addr: addr}
	s.up.Store(up)
	s.ewmaNs.Store(ewmaNs)
	return s
}

func TestRerankHealthyAndFastFirst(t *testing.T) {
	p := &Pool{servers: []*Server{
		newServer("slow-up:53", true, 50_000_000),  // 50ms, up
		newServer("dead:53", false, 1_000_000),     // fast but down
		newServer("fast-up:53", true, 5_000_000),   // 5ms, up
	}}
	p.rerank()
	order := *p.ranked.Load()
	if order[0].Addr != "fast-up:53" {
		t.Errorf("expected fastest healthy first, got %s", order[0].Addr)
	}
	if order[1].Addr != "slow-up:53" {
		t.Errorf("expected slower healthy second, got %s", order[1].Addr)
	}
	if order[2].Addr != "dead:53" {
		t.Errorf("expected down server last, got %s", order[2].Addr)
	}
}

func TestMarkFailDemotesAfterMaxFails(t *testing.T) {
	s := newServer("x:53", true, 0)
	const maxFails = 3
	s.markFail(maxFails)
	s.markFail(maxFails)
	if !s.up.Load() {
		t.Fatal("should still be up before reaching max_fails")
	}
	s.markFail(maxFails)
	if s.up.Load() {
		t.Fatal("should be down at max_fails")
	}
	// A success revives it and updates EWMA.
	s.markOK(2 * time.Millisecond)
	if !s.up.Load() {
		t.Fatal("markOK should revive the server")
	}
	if s.ewmaNs.Load() == 0 {
		t.Fatal("markOK should record latency")
	}
	if s.fails.Load() != 0 {
		t.Fatal("markOK should reset fail counter")
	}
}
