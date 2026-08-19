package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func mkResp(name string, ttl uint32, withAnswer bool) *dns.Msg {
	m := new(dns.Msg)
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	m.SetReply(q)
	if withAnswer {
		rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN A 1.2.3.4", name, ttl))
		m.Answer = append(m.Answer, rr)
	}
	return m
}

func TestStoreGetPositive(t *testing.T) {
	c := New(16, 1000, 86400, 900)
	resp := mkResp("example.com.", 300, true)
	c.Store("example.com.|1|1", resp, false)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.Id = 4242

	got := c.Get("example.com.|1|1", req)
	if got == nil {
		t.Fatal("expected cache hit")
	}
	if got.Id != 4242 {
		t.Errorf("id not rewritten: got %d", got.Id)
	}
	if len(got.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(got.Answer))
	}
	if ttl := got.Answer[0].Header().Ttl; ttl == 0 || ttl > 300 {
		t.Errorf("unexpected aged ttl: %d", ttl)
	}
}

func TestMissOnEmptyKey(t *testing.T) {
	c := New(16, 1000, 86400, 900)
	req := new(dns.Msg)
	req.SetQuestion("nope.com.", dns.TypeA)
	if c.Get("nope.com.|1|1", req) != nil {
		t.Error("expected miss")
	}
}

func TestPrefetchTriggersRefresh(t *testing.T) {
	c := New(16, 1000, 86400, 900)
	got := make(chan string, 4)
	// window huge so every near-hit qualifies; min 3 hits to be "popular".
	c.EnablePrefetch(1_000_000, 3, 1, func(key string) { got <- key })

	c.Store("hot.com.|1|1", mkResp("hot.com.", 3600, true), false)
	req := new(dns.Msg)
	req.SetQuestion("hot.com.", dns.TypeA)

	for i := 0; i < 5; i++ {
		if c.Get("hot.com.|1|1", req) == nil {
			t.Fatalf("expected hit on iteration %d", i)
		}
	}

	select {
	case k := <-got:
		if k != "hot.com.|1|1" {
			t.Errorf("prefetched wrong key: %q", k)
		}
	case <-time.After(time.Second):
		t.Fatal("expected a prefetch to be enqueued for a popular near-expiry entry")
	}
}

func TestPrefetchSkipsColdEntries(t *testing.T) {
	c := New(16, 1000, 86400, 900)
	fired := make(chan string, 4)
	c.EnablePrefetch(1_000_000, 100, 1, func(key string) { fired <- key })
	c.Store("cold.com.|1|1", mkResp("cold.com.", 3600, true), false)
	req := new(dns.Msg)
	req.SetQuestion("cold.com.", dns.TypeA)
	for i := 0; i < 5; i++ { // well below min_hits=100
		c.Get("cold.com.|1|1", req)
	}
	select {
	case <-fired:
		t.Fatal("cold entry should not be prefetched")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestServeStale(t *testing.T) {
	c := New(16, 1000, 86400, 900)
	c.EnableServeStale(3600, 30)
	c.Store("k.|1|1", mkResp("k.", 300, true), false)

	req := new(dns.Msg)
	req.SetQuestion("k.", dns.TypeA)

	// Force the entry past its fresh TTL but within the stale window.
	s := c.shardFor("k.|1|1")
	s.mu.Lock()
	s.m["k.|1|1"].storedAt -= 1000
	s.mu.Unlock()

	if c.Get("k.|1|1", req) != nil {
		t.Fatal("fresh Get must miss on an expired entry")
	}
	stale := c.GetStale("k.|1|1", req)
	if stale == nil {
		t.Fatal("GetStale should return the expired-but-in-window entry")
	}
	if len(stale.Answer) != 1 || stale.Answer[0].Header().Ttl != 30 {
		t.Errorf("stale answer should carry the short stale TTL (30), got %v", stale.Answer)
	}

	// Push it beyond the stale window => dropped, no stale served.
	s.mu.Lock()
	if e, ok := s.m["k.|1|1"]; ok {
		e.storedAt -= 4000
	}
	s.mu.Unlock()
	if c.GetStale("k.|1|1", req) != nil {
		t.Fatal("entry beyond stale window must not be served")
	}
}

func BenchmarkCacheGet(b *testing.B) {
	c := New(256, 20000, 86400, 900)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	c.Store("example.com.|1|1", mkResp("example.com.", 3600, true), false)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = c.Get("example.com.|1|1", req)
		}
	})
}
