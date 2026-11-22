package server

// Handler-level tests for wildcard answers (RFC 4592 sections 2.1.1 and 3.3):
// a wildcard synthesizes records owned by the query name, and only for a name
// that does not exist in the zone.

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
)

func wildcardZone(h *harness) {
	h.addZone(zoneName,
		rec("*.example.com.", dns.TypeA, "192.0.2.99"),
		rec("*.example.com.", dns.TypeTXT, "wild"),
		rec("www.example.com.", dns.TypeA, "192.0.2.10"),
		rec("mail.example.com.", dns.TypeMX, "mx.example.com."),
		// x.y.example.com. exists, so y.example.com. is an empty non-terminal.
		rec("x.y.example.com.", dns.TypeA, "192.0.2.50"),
		// A wildcard below an existing node.
		rec("*.sub.example.com.", dns.TypeA, "192.0.2.77"),
		rec("host.sub.example.com.", dns.TypeAAAA, "2001:db8::77"),
	)
}

func TestWildcardAnswerIsOwnedByTheQueryName(t *testing.T) {
	h := newHarness(t)
	wildcardZone(h)
	m := h.q("anything.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	if !m.Authoritative {
		t.Fatal("AA bit not set")
	}
	wantShape(t, m, "anything.example.com. A 192.0.2.99")

	m = h.q("Anything.Example.COM.", dns.TypeTXT)
	wantShape(t, m, "anything.example.com. TXT wild")

	// More than one label below the wildcard's parent, when the labels between do not exist.
	m = h.q("a.b.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "a.b.example.com. A 192.0.2.99")
}

func TestWildcardANYReturnsTheWildcardRecordsOwnedByTheQueryName(t *testing.T) {
	h := newHarness(t)
	wildcardZone(h)
	m := h.q("anything.example.com.", dns.TypeANY)
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 2 {
		t.Fatalf("answer=%v", m.Answer)
	}
	for _, rr := range m.Answer {
		if rr.Header().Name != "anything.example.com." {
			t.Fatalf("owner %s, want the query name", rr.Header().Name)
		}
	}
}

func TestNameWithItsOwnRecordOfTheTypeNeverGetsTheWildcardRecords(t *testing.T) {
	h := newHarness(t)
	wildcardZone(h)
	m := h.q("www.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "www.example.com. A 192.0.2.10")

	// An explicit record and the wildcard share a type: only the explicit one answers.
	m = h.q("www.example.com.", dns.TypeANY)
	wantShape(t, m, "www.example.com. A 192.0.2.10")
}

func TestNameThatExistsWithOtherTypesOnlyIsNODATANotTheWildcard(t *testing.T) {
	h := newHarness(t)
	wildcardZone(h)
	m := h.q("mail.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 0 {
		t.Fatalf("wildcard records returned for an existing name: %v", m.Answer)
	}
	wantSOAInAuthority(t, m, zoneName)

	m = h.q("www.example.com.", dns.TypeTXT)
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 0 {
		t.Fatalf("wildcard TXT returned for www: %v", m.Answer)
	}
}

func TestEmptyNonTerminalIsNODATANotTheWildcard(t *testing.T) {
	h := newHarness(t)
	wildcardZone(h)
	// y.example.com. has no records but x.y.example.com. exists below it.
	m := h.q("y.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 0 {
		t.Fatalf("wildcard records returned for an empty non-terminal: %v", m.Answer)
	}
	wantSOAInAuthority(t, m, zoneName)
}

func TestNameBelowAnExistingNodeUsesTheWildcardAtTheClosestEncloser(t *testing.T) {
	h := newHarness(t)
	wildcardZone(h)
	// The closest encloser of a.sub.example.com. is sub.example.com.: *.sub applies.
	m := h.q("a.sub.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "a.sub.example.com. A 192.0.2.77")

	// A name that exists under sub.example.com. is not covered by the wildcard.
	m = h.q("host.sub.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 0 {
		t.Fatalf("wildcard records returned for an existing name: %v", m.Answer)
	}

	// Deeper than the wildcard's parent: sub.example.com. is the closest encloser.
	m = h.q("p.q.sub.example.com.", dns.TypeA)
	wantShape(t, m, "p.q.sub.example.com. A 192.0.2.77")
}

func TestWildcardHigherUpDoesNotCoverANameBelowAnExistingNodeWithoutItsOwnWildcard(t *testing.T) {
	h := newHarness(t)
	wildcardZone(h)
	// y.example.com. exists (empty non-terminal), so *.example.com. is not the
	// wildcard that applies to z.y.example.com.; there is no *.y.example.com.
	m := h.q("z.y.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeNameError)
	if len(m.Answer) != 0 {
		t.Fatalf("answers for a name below an existing node with no wildcard of its own: %v", m.Answer)
	}
	wantSOAInAuthority(t, m, zoneName)
}

func TestWildcardDoesNotCoverTheApexOrTheZoneItself(t *testing.T) {
	h := newHarness(t)
	wildcardZone(h)
	m := h.q("example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 0 {
		t.Fatalf("wildcard answered for the apex: %v", m.Answer)
	}
}

func TestWildcardForATypeItLacksIsNODATAAtTheQueryName(t *testing.T) {
	h := newHarness(t)
	wildcardZone(h)
	m := h.q("anything.example.com.", dns.TypeAAAA)
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 0 {
		t.Fatalf("answer=%v", m.Answer)
	}
	wantSOAInAuthority(t, m, zoneName)
}

func TestNoWildcardMeansNXDOMAINForAMissingName(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	wantRcode(t, h.q("missing.example.com.", dns.TypeA), dns.RcodeNameError)
}

func TestWildcardIsSelectedPerClientView(t *testing.T) {
	h := newHarness(t, withViews(map[string][]string{"lan": {"10.0.0.0/8"}}))
	h.addZone(zoneName,
		rec("*.example.com.", dns.TypeA, "192.0.2.99"),
		// Only the lan view has a record of its own for "intra".
		authoritative.Record{Name: "intra.example.com.", Type: dns.TypeA, TTL: 300, Content: "10.0.0.5", View: "lan"},
	)
	wantShape(t, h.ask("10.1.2.3", "intra.example.com.", dns.TypeA), "intra.example.com. A 10.0.0.5")
	// Another view does not see the lan-only name, so the wildcard covers it.
	wantShape(t, h.ask(anyClientIP, "intra.example.com.", dns.TypeA), "intra.example.com. A 192.0.2.99")
}

func TestSignedZoneWildcardAnswerCarriesAVerifiableRRSIG(t *testing.T) {
	h := newHarness(t, withSigner())
	h.addZone(zoneName, rec("*.example.com.", dns.TypeA, "192.0.2.99"))
	m := h.q("anything.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	wantShape(t, m, "anything.example.com. A 192.0.2.99")
	verifyRRSIG(t, m.Answer, dns.TypeA, h.signer.DNSKEYs(zoneName))
	// Not asserted: the RRSIG labels field (wildcard expansion) and the proof that
	// the name does not exist; both belong to the DNSSEC wildcard follow-up.
}
