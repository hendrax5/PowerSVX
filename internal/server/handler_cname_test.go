package server

// Handler-level tests for CNAME answers (RFC 1034 section 3.6.2, RFC 2181
// section 10.1): a name that owns a CNAME answers every type but CNAME with the
// CNAME, and the chain is followed while it stays inside the hosted zones.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
)

// answerShape lists the answer section as "owner TYPE rdata" strings, without RRSIGs.
func answerShape(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		var data string
		switch v := rr.(type) {
		case *dns.CNAME:
			data = v.Target
		case *dns.A:
			data = v.A.String()
		case *dns.AAAA:
			data = v.AAAA.String()
		case *dns.MX:
			data = v.Mx
		case *dns.TXT:
			data = strings.Join(v.Txt, "")
		case *dns.RRSIG:
			continue
		}
		out = append(out, fmt.Sprintf("%s %s %s", rr.Header().Name, dns.TypeToString[rr.Header().Rrtype], data))
	}
	return out
}

func wantShape(t *testing.T, m *dns.Msg, want ...string) {
	t.Helper()
	got := answerShape(m)
	if strings.Join(got, " | ") != strings.Join(want, " | ") {
		t.Fatalf("answer:\n got  %v\n want %v", got, want)
	}
}

func TestCNAMEOnlyNameAnswersTheCNAMEForOtherTypes(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeCNAME, "web.elsewhere.test."))
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT} {
		m := h.q("www.example.com.", qt)
		wantRcode(t, m, dns.RcodeSuccess)
		if !m.Authoritative {
			t.Fatalf("%s: AA bit not set", dns.TypeToString[qt])
		}
		wantShape(t, m, "www.example.com. CNAME web.elsewhere.test.")
	}
}

func TestCNAMEOnlyNameAnswersCNAMEForANYAndForCNAMEItself(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName,
		rec("www.example.com.", dns.TypeCNAME, "web.example.com."),
		rec("web.example.com.", dns.TypeA, "192.0.2.10"),
	)
	m := h.q("www.example.com.", dns.TypeANY)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "www.example.com. CNAME web.example.com.")

	// CNAME asked explicitly is answered as before: the one record, target not followed.
	m = h.q("www.example.com.", dns.TypeCNAME)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "www.example.com. CNAME web.example.com.")
}

func TestCNAMEIntoTheSameZoneAddsTheTargetRecords(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName,
		rec("www.example.com.", dns.TypeCNAME, "web.example.com."),
		rec("web.example.com.", dns.TypeA, "192.0.2.10"),
		rec("web.example.com.", dns.TypeA, "192.0.2.11"),
		rec("web.example.com.", dns.TypeAAAA, "2001:db8::10"),
	)
	m := h.q("www.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m,
		"www.example.com. CNAME web.example.com.",
		"web.example.com. A 192.0.2.10",
		"web.example.com. A 192.0.2.11")
	m = h.q("www.example.com.", dns.TypeAAAA)
	wantShape(t, m, "www.example.com. CNAME web.example.com.", "web.example.com. AAAA 2001:db8::10")
}

func TestCNAMEChainInsideAZoneIsFollowedToTheEnd(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName,
		rec("a.example.com.", dns.TypeCNAME, "b.example.com."),
		rec("b.example.com.", dns.TypeCNAME, "c.example.com."),
		rec("c.example.com.", dns.TypeA, "192.0.2.30"),
	)
	m := h.q("a.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m,
		"a.example.com. CNAME b.example.com.",
		"b.example.com. CNAME c.example.com.",
		"c.example.com. A 192.0.2.30")
}

func TestCNAMEIntoAnotherHostedZoneAddsTheTargetRecords(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeCNAME, "web.other.test."))
	h.addZone("other.test.", rec("web.other.test.", dns.TypeA, "198.51.100.7"))
	m := h.q("www.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "www.example.com. CNAME web.other.test.", "web.other.test. A 198.51.100.7")
}

func TestCNAMEToANameOutsideTheHostedZonesReturnsOnlyTheCNAME(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeCNAME, "cdn.provider.invalid."))
	m := h.q("www.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "www.example.com. CNAME cdn.provider.invalid.")
	if len(m.Ns) != 0 {
		t.Fatalf("authority section for a CNAME leaving the hosted zones: %v", m.Ns)
	}
}

func TestCNAMELoopIsCutOffWithABoundedAnswer(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName,
		rec("a.example.com.", dns.TypeCNAME, "b.example.com."),
		rec("b.example.com.", dns.TypeCNAME, "a.example.com."),
		rec("self.example.com.", dns.TypeCNAME, "self.example.com."),
	)
	m := h.q("a.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "a.example.com. CNAME b.example.com.", "b.example.com. CNAME a.example.com.")

	m = h.q("self.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "self.example.com. CNAME self.example.com.")
}

func TestCNAMEChainLongerThanTheLimitIsCutOff(t *testing.T) {
	h := newHarness(t)
	var recs []authoritative.Record
	n := authoritative.MaxCNAMEChain + 5
	for i := 0; i < n; i++ {
		recs = append(recs, rec(fmt.Sprintf("n%d.example.com.", i), dns.TypeCNAME, fmt.Sprintf("n%d.example.com.", i+1)))
	}
	recs = append(recs, rec(fmt.Sprintf("n%d.example.com.", n), dns.TypeA, "192.0.2.99"))
	h.addZone(zoneName, recs...)
	m := h.q("n0.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	if got := len(rrsOfType(m.Answer, dns.TypeCNAME)); got != authoritative.MaxCNAMEChain {
		t.Fatalf("followed %d CNAMEs, want the limit of %d", got, authoritative.MaxCNAMEChain)
	}
	if len(answerA(t, m)) != 0 {
		t.Fatal("record beyond the chain limit was answered")
	}
}

func TestCNAMEToAnExistingNameWithoutTheTypeIsNODATAAfterTheCNAME(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName,
		rec("www.example.com.", dns.TypeCNAME, "web.example.com."),
		rec("web.example.com.", dns.TypeAAAA, "2001:db8::10"),
	)
	m := h.q("www.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "www.example.com. CNAME web.example.com.")
	wantSOAInAuthority(t, m, zoneName)
}

func TestCNAMEToAMissingNameInAHostedZoneIsNXDOMAINAfterTheCNAME(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeCNAME, "gone.other.test."))
	h.addZone("other.test.")
	m := h.q("www.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeNameError)
	wantShape(t, m, "www.example.com. CNAME gone.other.test.")
	wantSOAInAuthority(t, m, "other.test.")
}

func TestCNAMEAtAWildcardAnswersWithTheQueryNameAsOwner(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName,
		rec("*.example.com.", dns.TypeCNAME, "web.example.com."),
		rec("web.example.com.", dns.TypeA, "192.0.2.10"),
	)
	m := h.q("foo.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "foo.example.com. CNAME web.example.com.", "web.example.com. A 192.0.2.10")
}

func TestCNAMEFollowingRespectsTheClientsView(t *testing.T) {
	h := newHarness(t, withViews(map[string][]string{"lan": {"10.0.0.0/8"}}))
	h.addZone(zoneName,
		rec("www.example.com.", dns.TypeCNAME, "web.example.com."),
		authoritative.Record{Name: "web.example.com.", Type: dns.TypeA, TTL: 300, Content: "10.0.0.5", View: "lan"},
		authoritative.Record{Name: "web.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.5", View: "default"},
	)
	wantShape(t, h.ask("10.1.2.3", "www.example.com.", dns.TypeA),
		"www.example.com. CNAME web.example.com.", "web.example.com. A 10.0.0.5")
	wantShape(t, h.ask(anyClientIP, "www.example.com.", dns.TypeA),
		"www.example.com. CNAME web.example.com.", "web.example.com. A 192.0.2.5")
}

func TestSignedZoneCNAMEAnswerCarriesRRSIGsForTheCNAMEAndTheFollowedRecords(t *testing.T) {
	h := newHarness(t, withSigner())
	h.addZone(zoneName,
		rec("www.example.com.", dns.TypeCNAME, "web.example.com."),
		rec("web.example.com.", dns.TypeA, "192.0.2.10"),
	)
	keys := h.signer.DNSKEYs(zoneName)
	m := h.q("www.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "www.example.com. CNAME web.example.com.", "web.example.com. A 192.0.2.10")
	verifyRRSIG(t, m.Answer, dns.TypeCNAME, keys)
	verifyRRSIG(t, m.Answer, dns.TypeA, keys)

	// Without DO there is no signature.
	if sigs := rrsOfType(h.q("www.example.com.", dns.TypeA).Answer, dns.TypeRRSIG); len(sigs) != 0 {
		t.Fatalf("RRSIG without DO: %v", sigs)
	}
}

func TestSignedZonesSignEachPartOfACrossZoneChainWithItsOwnKey(t *testing.T) {
	h := newHarness(t, withSigner())
	h.addZone(zoneName, rec("www.example.com.", dns.TypeCNAME, "web.other.test."))
	h.addZone("other.test.", rec("web.other.test.", dns.TypeA, "198.51.100.7"))
	m := h.q("www.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "www.example.com. CNAME web.other.test.", "web.other.test. A 198.51.100.7")
	verifyRRSIG(t, m.Answer, dns.TypeCNAME, h.signer.DNSKEYs(zoneName))
	verifyRRSIG(t, m.Answer, dns.TypeA, h.signer.DNSKEYs("other.test."))
}
