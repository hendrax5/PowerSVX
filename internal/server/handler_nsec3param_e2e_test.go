package server

// NSEC3PARAM at the apex of NSEC3-signed zones (RFC 5155 section 4): served and
// signed, sent in zone transfers, and always in step with the signing policy.

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/dnssec"
)

func nsec3paramOf(rrs []dns.RR) *dns.NSEC3PARAM {
	for _, rr := range rrs {
		if n, ok := rr.(*dns.NSEC3PARAM); ok {
			return n
		}
	}
	return nil
}

func wantNSEC3PARAMMatchesPolicy(t *testing.T, h *harness, rr *dns.NSEC3PARAM) {
	t.Helper()
	if rr == nil {
		t.Fatal("no NSEC3PARAM")
	}
	if rr.Hash != dns.SHA1 || rr.Flags != 0 || rr.Iterations != 1 || rr.Salt != h.nsec3Salt() || dns.CanonicalName(rr.Hdr.Name) != zoneName {
		t.Fatalf("NSEC3PARAM %v does not match the zone policy (salt %s)", rr, h.nsec3Salt())
	}
}

func TestNSEC3ZoneServesASignedNSEC3PARAMAtTheApex(t *testing.T) {
	h := nsec3Zone(t, "")
	m := h.q("example.com.", dns.TypeNSEC3PARAM, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	wantNSEC3PARAMMatchesPolicy(t, h, nsec3paramOf(m.Answer))
	verifyEveryRRset(t, m, m.Answer, h.signer.DNSKEYs(zoneName))
	if len(rrsOfType(m.Answer, dns.TypeRRSIG)) != 1 {
		t.Fatalf("want one RRSIG, got %v", m.Answer)
	}
	if m.Answer[0].Header().Ttl != 300 {
		t.Errorf("TTL = %d, want the SOA minimum 300", m.Answer[0].Header().Ttl)
	}
}

func TestNSEC3PARAMHasNoSignatureWithoutDNSSECOK(t *testing.T) {
	h := nsec3Zone(t, "")
	m := h.q("example.com.", dns.TypeNSEC3PARAM)
	wantNSEC3PARAMMatchesPolicy(t, h, nsec3paramOf(m.Answer))
	if len(rrsOfType(m.Answer, dns.TypeRRSIG)) != 0 {
		t.Fatalf("RRSIG without DO: %v", m.Answer)
	}
}

func TestNSEC3PARAMIsOnlyAtTheApex(t *testing.T) {
	h := nsec3Zone(t, "")
	m := h.q("www.example.com.", dns.TypeNSEC3PARAM, withDO())
	if nsec3paramOf(m.Answer) != nil {
		t.Fatalf("NSEC3PARAM below the apex: %v", m.Answer)
	}
}

func TestNSECAndUnsignedZonesHaveNoNSEC3PARAM(t *testing.T) {
	h := nsecZone(t)
	m := h.q("example.com.", dns.TypeNSEC3PARAM, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 0 {
		t.Fatalf("NSEC zone answered NSEC3PARAM: %v", m.Answer)
	}
	plain := newHarness(t)
	plain.addZone(zoneName)
	m = plain.q("example.com.", dns.TypeNSEC3PARAM, withDO())
	if len(m.Answer) != 0 {
		t.Fatalf("unsigned zone answered NSEC3PARAM: %v", m.Answer)
	}
}

func TestNSEC3PARAMFollowsTheDenialMethodAndTheSalt(t *testing.T) {
	h := nsec3Zone(t, "")
	opts := func(nsec3 bool, salt string) {
		t.Helper()
		if err := h.signer.EnsureWithOptions(zoneName, dnssec.SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: nsec3, Salt: salt}); err != nil {
			t.Fatal(err)
		}
	}
	ask := func() *dns.Msg { return h.q("example.com.", dns.TypeNSEC3PARAM, withDO()) }

	opts(true, "a1b2c3d4e5")
	m := ask()
	wantNSEC3PARAMMatchesPolicy(t, h, nsec3paramOf(m.Answer))
	if nsec3paramOf(m.Answer).Salt != "a1b2c3d4e5" {
		t.Fatalf("salt change not served: %v", m.Answer)
	}
	verifyEveryRRset(t, m, m.Answer, h.signer.DNSKEYs(zoneName))

	// The chain uses the same salt as the record.
	nx := h.q("missing.example.com.", dns.TypeA, withDO())
	for _, n := range nsec3sOf(nx) {
		if n.Salt != "a1b2c3d4e5" {
			t.Fatalf("NSEC3 salt %s differs from NSEC3PARAM", n.Salt)
		}
	}

	opts(false, "")
	if m := ask(); len(m.Answer) != 0 {
		t.Fatalf("stale NSEC3PARAM after switching to NSEC: %v", m.Answer)
	}
	opts(true, "0badc0de")
	if got := nsec3paramOf(ask().Answer); got == nil || got.Salt != "0badc0de" {
		t.Fatalf("NSEC3PARAM after switching back: %v", got)
	}

	// A new key algorithm re-signs the zone with a fresh salt; the record follows.
	if err := h.signer.EnsureWithOptions(zoneName, dnssec.SignOptions{Algorithm: dns.ECDSAP384SHA384, NSEC3: true}); err != nil {
		t.Fatal(err)
	}
	m = ask()
	wantNSEC3PARAMMatchesPolicy(t, h, nsec3paramOf(m.Answer))
	verifyEveryRRset(t, m, m.Answer, h.signer.DNSKEYs(zoneName))
}

func TestNSEC3ApexBitmapListsNSEC3PARAMAndNSECZonesDoNot(t *testing.T) {
	h := nsec3Zone(t, "")
	m := h.q("example.com.", dns.TypeTXT, withDO())
	n := matchingNSEC3(nsec3sOf(m), "example.com.")
	found := false
	for _, typ := range n.TypeBitMap {
		found = found || typ == dns.TypeNSEC3PARAM
	}
	if !found {
		t.Fatalf("apex NSEC3 bitmap %v lacks NSEC3PARAM", n.TypeBitMap)
	}
	z := nsecZone(t)
	for _, n := range nsecsByOwner(z.q("example.com.", dns.TypeTXT, withDO())) {
		for _, typ := range n.TypeBitMap {
			if typ == dns.TypeNSEC3PARAM {
				t.Fatalf("NSEC bitmap lists NSEC3PARAM: %v", n.TypeBitMap)
			}
		}
	}
}

func TestAXFRAndIXFRIncludeNSEC3PARAMOfAnNSEC3Zone(t *testing.T) {
	h := nsec3Zone(t, "", withConfig(allowTransfer))
	rrs, _ := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeAXFR, 0)
	wantNSEC3PARAMMatchesPolicy(t, h, nsec3paramOf(rrs))
	if len(rrsOfType(rrs, dns.TypeNSEC3PARAM)) != 1 {
		t.Fatalf("want exactly one NSEC3PARAM in the AXFR: %v", rrs)
	}

	// A client behind the current serial gets the zone in full, NSEC3PARAM included.
	cur := h.auth.CurrentSOASerial(zoneName)
	rrs, _ = h.transfer(newWriter(anyClientIP), zoneName, dns.TypeIXFR, cur-1)
	wantNSEC3PARAMMatchesPolicy(t, h, nsec3paramOf(rrs))

	// A client that is up to date gets the SOA only.
	rrs, _ = h.transfer(newWriter(anyClientIP), zoneName, dns.TypeIXFR, cur)
	if len(rrs) != 1 {
		t.Fatalf("up-to-date IXFR should be the SOA only, got %v", rrs)
	}
}

func TestTransferCarriesNoNSEC3PARAMAfterTheZoneLeavesNSEC3(t *testing.T) {
	h := nsec3Zone(t, "", withConfig(allowTransfer))
	if err := h.signer.EnsureWithOptions(zoneName, dnssec.SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: false}); err != nil {
		t.Fatal(err)
	}
	rrs, _ := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeAXFR, 0)
	if nsec3paramOf(rrs) != nil {
		t.Fatalf("stale NSEC3PARAM in AXFR: %v", rrs)
	}
}

func TestTransferOfNSECAndUnsignedZonesHasNoNSEC3PARAM(t *testing.T) {
	h := newHarness(t, withSigner(), withConfig(allowTransfer))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	rrs, _ := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeAXFR, 0)
	if nsec3paramOf(rrs) != nil {
		t.Fatalf("NSEC zone AXFR has NSEC3PARAM: %v", rrs)
	}
}
