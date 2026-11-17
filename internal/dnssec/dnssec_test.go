package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestParseMode(t *testing.T) {
	if ParseMode("validate", false) != ModeValidate {
		t.Fatal("expected validate")
	}
	if ParseMode("opportunistic", false) != ModeOpportunistic {
		t.Fatal("expected opportunistic")
	}
	if ParseMode("off", false) != ModeOff {
		t.Fatal("expected off")
	}
	if ParseMode("", true) != ModeValidate {
		t.Fatal("legacy enabled -> validate")
	}
}

func TestApplyUpstreamAD(t *testing.T) {
	v := New(ModeValidate)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.AuthenticatedData = true
	msg.Rcode = dns.RcodeSuccess

	sf, res := v.Apply(msg)
	if sf {
		t.Fatal("should not servfail")
	}
	if !res.Authenticated || !msg.AuthenticatedData {
		t.Fatalf("expected AD set, res=%+v", res)
	}
}

func TestApplyOpportunisticNoAD(t *testing.T) {
	v := New(ModeOpportunistic)
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	sf, res := v.Apply(msg)
	if sf {
		t.Fatal("opportunistic must not servfail")
	}
	if msg.AuthenticatedData {
		t.Fatal("AD should remain false")
	}
	_ = res
}

func TestForgedADRejectedOnTamperedRRSIG(t *testing.T) {
	v := New(ModeValidate)
	s := NewSigner(t.TempDir())
	if err := s.Ensure("example.com."); err != nil {
		t.Fatal(err)
	}
	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	req.SetEdns0(1232, true)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{1, 2, 3, 4}},
	}
	s.SignResponse("example.com.", req, resp)
	// Attach DNSKEY and tamper A record while setting upstream AD=true
	resp.Extra = append(resp.Extra, s.DNSKEYs("example.com.")...)
	resp.Answer[0].(*dns.A).A = []byte{9, 9, 9, 9}
	resp.AuthenticatedData = true

	sf, res := v.Apply(resp)
	if !sf || !res.Bogus {
		t.Fatalf("expected SERVFAIL bogus on tampered RRSIG even with AD=true, got sf=%v res=%+v", sf, res)
	}
}
