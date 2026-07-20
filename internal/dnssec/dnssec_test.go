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
