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

func TestSignerED25519NSEC3AndRollover(t *testing.T) {
	dir := t.TempDir()
	s := NewSigner(dir)
	zone := "isp.co.id."
	if err := s.EnsureWithOptions(zone, SignOptions{Algorithm: dns.ED25519, NSEC3: true}); err != nil {
		t.Fatal(err)
	}
	dsBefore, err := s.DS(zone)
	if err != nil || dsBefore.Algorithm != dns.ED25519 {
		t.Fatalf("unexpected DS: %+v err=%v", dsBefore, err)
	}
	if err := s.RolloverZSK(zone); err != nil {
		t.Fatal(err)
	}
	dsAfter, err := s.DS(zone)
	if err != nil || dsAfter.Digest != dsBefore.Digest {
		t.Fatalf("KSK DS changed during ZSK rollover: before=%s after=%s", dsBefore.Digest, dsAfter.Digest)
	}

	req := new(dns.Msg)
	req.SetQuestion("missing.isp.co.id.", dns.TypeA)
	req.SetEdns0(1232, true)
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)
	s.SignDenialForNames(zone, "missing.isp.co.id.", map[string][]uint16{zone: {dns.TypeSOA}, "www.isp.co.id.": {dns.TypeA}}, req, resp)
	hasNSEC3 := false
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			hasNSEC3 = true
		}
	}
	if !hasNSEC3 {
		t.Fatalf("expected NSEC3 record in denial section: %v", resp.Ns)
	}
}
