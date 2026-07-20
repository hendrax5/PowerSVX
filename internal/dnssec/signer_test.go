package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestSignerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewSigner(dir)
	zone := "example.com."
	if err := s.Ensure(zone); err != nil {
		t.Fatal(err)
	}
	if !s.Enabled(zone) {
		t.Fatal("expected enabled")
	}
	ds, err := s.DS(zone)
	if err != nil || ds == nil {
		t.Fatalf("ds: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion(zone, dns.TypeA)
	req.SetEdns0(1232, true)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{1, 2, 3, 4},
		},
	}
	s.SignResponse(zone, req, resp)
	hasSig := false
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			hasSig = true
		}
	}
	if !hasSig {
		t.Fatalf("missing RRSIG: %v", resp.Answer)
	}

	req2 := new(dns.Msg)
	req2.SetQuestion(zone, dns.TypeDNSKEY)
	resp2 := new(dns.Msg)
	resp2.SetReply(req2)
	s.SignResponse(zone, req2, resp2)
	if len(resp2.Answer) < 2 {
		t.Fatalf("dnskey answer: %v", resp2.Answer)
	}
}
