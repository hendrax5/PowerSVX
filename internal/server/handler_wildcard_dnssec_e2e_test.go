package server

// DNSSEC for answers synthesized from a wildcard (RFC 4035 sections 3.1.3.3 and
// 5.3.4, RFC 5155 section 7.2.6): the RRSIG is the wildcard record's, its labels
// field shows the expansion, and the authority section proves the query name
// does not exist.

import (
	"testing"

	"github.com/miekg/dns"
)

func wantWildcardRRSIG(t *testing.T, m *dns.Msg, owner string, typ uint16, labels uint8) {
	t.Helper()
	for _, rr := range m.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == typ && dns.CanonicalName(sig.Hdr.Name) == owner {
			if sig.Labels != labels {
				t.Fatalf("RRSIG over %s %s has labels=%d want %d", owner, dns.TypeToString[typ], sig.Labels, labels)
			}
			return
		}
	}
	t.Fatalf("no RRSIG over %s %s in %v", owner, dns.TypeToString[typ], m.Answer)
}

func nsecWildcardZone(t *testing.T) *harness {
	t.Helper()
	h := nsecZone(t)
	h.auth.AddRecord(zoneName, rec("*.w.example.com.", dns.TypeA, "192.0.2.77"))
	h.auth.AddRecord(zoneName, rec("*.c.example.com.", dns.TypeCNAME, "b.example.com."))
	return h
}

func TestNSECZoneWildcardAnswerCarriesTheWildcardRRSIGAndTheNSECOfTheMissingName(t *testing.T) {
	h := nsecWildcardZone(t)
	m := h.q("foo.w.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	wantA(t, m, "192.0.2.77")
	if m.Answer[0].Header().Name != "foo.w.example.com." {
		t.Fatalf("owner = %s", m.Answer[0].Header().Name)
	}
	wantWildcardRRSIG(t, m, "foo.w.example.com.", dns.TypeA, 3)
	// foo.w sorts after *.w and before a.z: the wildcard's own NSEC covers it.
	got := nsecsByOwner(m)
	if len(got) != 1 {
		t.Fatalf("want 1 covering NSEC, got %v", m.Ns)
	}
	wantNSEC(t, got, "*.w.example.com.", "a.z.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)
	verifyEveryRRset(t, m, append(append([]dns.RR{}, m.Answer...), m.Ns...), h.signer.DNSKEYs(zoneName))
}

func TestNSECZoneWildcardAnswerBelowAnEmptyNameUsesTheClosestEncloserLabels(t *testing.T) {
	h := nsecWildcardZone(t)
	m := h.q("a.b.w.example.com.", dns.TypeA, withDO())
	wantA(t, m, "192.0.2.77")
	wantWildcardRRSIG(t, m, "a.b.w.example.com.", dns.TypeA, 3)
	verifyEveryRRset(t, m, append(append([]dns.RR{}, m.Answer...), m.Ns...), h.signer.DNSKEYs(zoneName))
	if len(rrsOfType(m.Ns, dns.TypeNSEC)) != 1 {
		t.Fatalf("want the covering NSEC, got %v", m.Ns)
	}
}

func TestNSECZoneNameWithItsOwnRecordGetsNoWildcardProof(t *testing.T) {
	h := nsecWildcardZone(t)
	h.auth.AddRecord(zoneName, rec("own.w.example.com.", dns.TypeA, "192.0.2.5"))
	m := h.q("own.w.example.com.", dns.TypeA, withDO())
	wantA(t, m, "192.0.2.5")
	wantWildcardRRSIG(t, m, "own.w.example.com.", dns.TypeA, 4)
	if len(m.Ns) != 0 {
		t.Fatalf("authority section on a positive answer: %v", m.Ns)
	}
}

func TestNSECZoneWildcardCNAMEChainSignsEachStepAndProvesTheMissingName(t *testing.T) {
	h := nsecWildcardZone(t)
	m := h.q("x.c.example.com.", dns.TypeA, withDO())
	if len(rrsOfType(m.Answer, dns.TypeCNAME)) != 1 || len(rrsOfType(m.Answer, dns.TypeA)) != 1 {
		t.Fatalf("want the synthesized CNAME and its target's A: %v", m.Answer)
	}
	wantWildcardRRSIG(t, m, "x.c.example.com.", dns.TypeCNAME, 3)
	wantWildcardRRSIG(t, m, "b.example.com.", dns.TypeA, 3)
	verifyEveryRRset(t, m, append(append([]dns.RR{}, m.Answer...), m.Ns...), h.signer.DNSKEYs(zoneName))
	if len(rrsOfType(m.Ns, dns.TypeNSEC)) != 1 {
		t.Fatalf("want one covering NSEC for x.c.example.com., got %v", m.Ns)
	}
}

func TestWildcardAnswerHasNoProofOrWildcardSignatureWithoutDNSSECOK(t *testing.T) {
	h := nsecWildcardZone(t)
	m := h.q("foo.w.example.com.", dns.TypeA)
	wantA(t, m, "192.0.2.77")
	if len(m.Ns) != 0 || len(rrsOfType(m.Answer, dns.TypeRRSIG)) != 0 {
		t.Fatalf("DNSSEC records without DO: %v %v", m.Answer, m.Ns)
	}
}

func TestNSEC3ZoneWildcardAnswerCarriesTheClosestEncloserProof(t *testing.T) {
	for i := 0; i < 20; i++ {
		h := nsec3Zone(t, "")
		h.auth.AddRecord(zoneName, rec("*.w.example.com.", dns.TypeA, "192.0.2.77"))
		for _, q := range []string{"foo.w.example.com.", "a.b.w.example.com."} {
			m := h.q(q, dns.TypeA, withDO())
			wantRcode(t, m, dns.RcodeSuccess)
			wantA(t, m, "192.0.2.77")
			wantWildcardRRSIG(t, m, q, dns.TypeA, 3)
			ns := nsec3sOf(m)
			if matchingNSEC3(ns, "w.example.com.") == nil {
				t.Fatalf("%s: closest encloser w.example.com. has no matching NSEC3: %v", q, m.Ns)
			}
			next := q
			if q == "a.b.w.example.com." {
				next = "b.w.example.com."
			}
			if coveringNSEC3(ns, next) == nil {
				t.Fatalf("%s: next closer name %s is not covered: %v", q, next, m.Ns)
			}
			verifyEveryRRset(t, m, append(append([]dns.RR{}, m.Answer...), m.Ns...), h.signer.DNSKEYs(zoneName))
		}
	}
}
