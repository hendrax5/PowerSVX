package server

import (
	"log/slog"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
)

func TestAggressiveNSECSynthesizesNXDOMAIN(t *testing.T) {
	cfg := config.Default()
	tier := cache.NewTier(cache.NewL1(100), nil, time.Minute, time.Minute)
	s := New(cfg, Deps{Cache: tier}, slog.Default())
	s.nsec.AddFrom([]dns.RR{&dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "c.example.com.",
		TypeBitMap: []uint16{dns.TypeA},
	}})

	req := new(dns.Msg)
	req.SetQuestion("b.example.com.", dns.TypeA)
	resp, _, err := s.ServeDNSMsg(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode=%d want NXDOMAIN", resp.Rcode)
	}
	if !resp.AuthenticatedData {
		t.Fatal("synthesized NXDOMAIN must set AD")
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("want covering NSEC in authority, got %d RRs", len(resp.Ns))
	}
}

func TestRememberNSECOnlyWhenAD(t *testing.T) {
	s := New(config.Default(), Deps{Cache: cache.NewTier(cache.NewL1(10), nil, time.Minute, time.Minute)}, slog.Default())
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Ttl: 300},
		NextDomain: "c.example.com.",
	}
	unsigned := new(dns.Msg)
	unsigned.SetQuestion("b.example.com.", dns.TypeA)
	unsigned.Rcode = dns.RcodeNameError
	unsigned.Ns = []dns.RR{n}
	s.rememberNSEC(unsigned)
	if s.nsec.Cover("b.example.com.") != nil {
		t.Fatal("must not cache NSEC from a non-AD response")
	}

	unsigned.AuthenticatedData = true
	s.rememberNSEC(unsigned)
	if s.nsec.Cover("b.example.com.") == nil {
		t.Fatal("AD NXDOMAIN should cache the covering NSEC")
	}
}
