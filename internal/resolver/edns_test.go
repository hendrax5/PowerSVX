package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestSetEDNS0DoesNotDuplicateOPT(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(1232, false)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "aabbccdd",
	})

	setEDNS0(req, 1232, true)

	var opts int
	for _, rr := range req.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			opts++
		}
	}
	if opts != 1 {
		t.Fatalf("OPT count=%d want 1 (Extra=%v)", opts, req.Extra)
	}
	got := req.IsEdns0()
	if got == nil || !got.Do() || got.UDPSize() != 1232 {
		t.Fatalf("edns=%v", got)
	}
	for _, o := range got.Option {
		if _, ok := o.(*dns.EDNS0_COOKIE); ok {
			t.Fatal("client COOKIE must not be forwarded upstream")
		}
	}
}

func TestPrepareClientResponseEchoesCookie(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(1232, false)
	req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "deadbeef",
	})

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{93, 184, 216, 34}},
	}
	// Simulate upstream OPT (different cookie / ECS leftovers).
	resp.SetEdns0(512, true)
	resp.IsEdns0().Option = append(resp.IsEdns0().Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "upstream",
	})

	PrepareClientResponse(req, resp, 1232)

	var opts int
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			opts++
		}
	}
	if opts != 1 {
		t.Fatalf("OPT count=%d", opts)
	}
	opt := resp.IsEdns0()
	if opt == nil || opt.UDPSize() != 1232 {
		t.Fatalf("edns=%v", opt)
	}
	found := false
	for _, o := range opt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok {
			found = true
			if c.Cookie != "deadbeef" {
				t.Fatalf("cookie=%q", c.Cookie)
			}
		}
	}
	if !found {
		t.Fatal("expected echoed client COOKIE")
	}
}

func TestPrepareClientResponseClampsUDPSize(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)
	req.SetEdns0(4096, false) // client advertises larger than listen budget

	resp := new(dns.Msg)
	resp.SetReply(req)
	PrepareClientResponse(req, resp, 1232)
	opt := resp.IsEdns0()
	if opt == nil || opt.UDPSize() != 1232 {
		t.Fatalf("want clamped 1232, got %v", opt)
	}
}
