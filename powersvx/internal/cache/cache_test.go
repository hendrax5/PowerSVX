package cache

import (
	"fmt"
	"testing"

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
