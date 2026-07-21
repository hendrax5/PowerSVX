package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestHasAnswerDoesNotTreatCNAMEAsFinalForA(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("finance.yahoo.com.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "finance.yahoo.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: "fo-finance-ycpi-cf.gycpi.b.yahoodns.net.",
		},
	}
	if hasAnswer(msg, "finance.yahoo.com.", dns.TypeA) {
		t.Fatal("CNAME-only response must not count as final A answer")
	}
	if extractCNAME(msg, "finance.yahoo.com.") == "" {
		t.Fatal("expected extractCNAME to find target")
	}

	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "fo-finance-ycpi-cf.gycpi.b.yahoodns.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{1, 2, 3, 4},
	})
	// Still no A for the qname itself — hasAnswer looks at qname match only.
	if hasAnswer(msg, "finance.yahoo.com.", dns.TypeA) {
		t.Fatal("A for CNAME target should not satisfy hasAnswer for original qname")
	}

	msg2 := new(dns.Msg)
	msg2.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{1, 2, 3, 4},
		},
	}
	if !hasAnswer(msg2, "example.com.", dns.TypeA) {
		t.Fatal("expected A answer to count")
	}

	cnameQ := new(dns.Msg)
	cnameQ.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "finance.yahoo.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: "fo-finance-ycpi-cf.gycpi.b.yahoodns.net.",
		},
	}
	if !hasAnswer(cnameQ, "finance.yahoo.com.", dns.TypeCNAME) {
		t.Fatal("CNAME query should accept CNAME answer")
	}
}
