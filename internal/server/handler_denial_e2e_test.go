package server

// End-to-end tests for authenticated denial of existence in NSEC-signed zones
// (RFC 4034 section 4, RFC 4035 section 3.1.3). The independent validator test
// lives in test/dnssecdenial; these run in-process on every `go test`.

import (
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// verifyEveryRRset checks that each RRset in the section (other than RRSIG) has an
// RRSIG that verifies with one of the zone keys, and that the message packs.
func verifyEveryRRset(t *testing.T, m *dns.Msg, rrs []dns.RR, keys []dns.RR) {
	t.Helper()
	if _, err := m.Pack(); err != nil {
		t.Fatalf("reply does not pack: %v", err)
	}
	type setKey struct {
		name string
		typ  uint16
	}
	sets := map[setKey][]dns.RR{}
	var order []setKey
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		k := setKey{dns.CanonicalName(rr.Header().Name), rr.Header().Rrtype}
		if _, ok := sets[k]; !ok {
			order = append(order, k)
		}
		sets[k] = append(sets[k], rr)
	}
	for _, k := range order {
		verified := false
		for _, rr := range rrs {
			sig, ok := rr.(*dns.RRSIG)
			if !ok || sig.TypeCovered != k.typ || dns.CanonicalName(sig.Hdr.Name) != k.name {
				continue
			}
			for _, kk := range keys {
				key, ok := kk.(*dns.DNSKEY)
				if !ok || key.KeyTag() != sig.KeyTag {
					continue
				}
				if err := sig.Verify(key, sets[k]); err != nil {
					t.Fatalf("RRSIG over %s %s does not verify: %v", k.name, dns.TypeToString[k.typ], err)
				}
				if !sig.ValidityPeriod(time.Now()) {
					t.Fatalf("RRSIG over %s %s outside its validity period", k.name, dns.TypeToString[k.typ])
				}
				verified = true
			}
		}
		if !verified {
			t.Fatalf("no verifiable RRSIG over %s %s in %v", k.name, dns.TypeToString[k.typ], rrs)
		}
	}
}

func nsecsByOwner(m *dns.Msg) map[string]*dns.NSEC {
	out := map[string]*dns.NSEC{}
	for _, rr := range rrsOfType(m.Ns, dns.TypeNSEC) {
		out[dns.CanonicalName(rr.Header().Name)] = rr.(*dns.NSEC)
	}
	return out
}

func wantNSEC(t *testing.T, got map[string]*dns.NSEC, owner, next string, types ...uint16) {
	t.Helper()
	n, ok := got[owner]
	if !ok {
		t.Fatalf("no NSEC owned by %s, have %v", owner, got)
	}
	if dns.CanonicalName(n.NextDomain) != next {
		t.Errorf("NSEC %s next=%s want %s", owner, n.NextDomain, next)
	}
	if !reflect.DeepEqual(n.TypeBitMap, types) {
		t.Errorf("NSEC %s bitmap=%v want %v", owner, n.TypeBitMap, types)
	}
}

// nsecZone has names that sort differently as plain strings and as DNSSEC
// canonical order, and an empty non-terminal (z.example.com. has no records,
// a.z.example.com. does).
func nsecZone(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, withSigner())
	h.addZone(zoneName,
		rec("example.com.", dns.TypeNS, "ns1.example.com."),
		rec("b.example.com.", dns.TypeA, "192.0.2.1"),
		rec("b.example.com.", dns.TypeTXT, "hello"),
		rec("a.z.example.com.", dns.TypeAAAA, "2001:db8::1"),
	)
	return h
}

func TestSignedZoneNXDOMAINCarriesTheNSECChainProof(t *testing.T) {
	h := nsecZone(t)
	m := h.q("m.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeNameError)
	wantSOAInAuthority(t, m, zoneName)
	got := nsecsByOwner(m)
	if len(got) != 2 {
		t.Fatalf("want 2 NSEC (name and wildcard), got %v", m.Ns)
	}
	// m.example.com. falls in the gap b -> a.z; the wildcard *.example.com. in
	// the gap example.com. -> b (the empty non-terminal z is not in the chain).
	wantNSEC(t, got, "b.example.com.", "a.z.example.com.", dns.TypeA, dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC)
	wantNSEC(t, got, "example.com.", "b.example.com.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY)
	verifyEveryRRset(t, m, m.Ns, h.signer.DNSKEYs(zoneName))
}

func TestSignedZoneNXDOMAINBelowAnExistingNameProvesThatNameIsTheClosestEncloser(t *testing.T) {
	h := nsecZone(t)
	m := h.q("x.b.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeNameError)
	got := nsecsByOwner(m)
	// x.b falls after b and before a.z; *.b.example.com. falls in the same gap,
	// so one record proves both.
	if len(got) != 1 {
		t.Fatalf("want 1 NSEC covering both the name and its wildcard, got %v", m.Ns)
	}
	wantNSEC(t, got, "b.example.com.", "a.z.example.com.", dns.TypeA, dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC)
	verifyEveryRRset(t, m, m.Ns, h.signer.DNSKEYs(zoneName))
}

func TestSignedZoneNXDOMAINAfterTheLastNameWrapsToTheApex(t *testing.T) {
	h := nsecZone(t)
	m := h.q("zz.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeNameError)
	got := nsecsByOwner(m)
	wantNSEC(t, got, "a.z.example.com.", "example.com.", dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC)
	verifyEveryRRset(t, m, m.Ns, h.signer.DNSKEYs(zoneName))
}

func TestSignedZoneNXDOMAINIsCaseInsensitiveInTheChain(t *testing.T) {
	h := nsecZone(t)
	m := h.q("M.Example.COM.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeNameError)
	wantNSEC(t, nsecsByOwner(m), "b.example.com.", "a.z.example.com.", dns.TypeA, dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC)
}

func TestSignedZoneNODATACarriesTheMatchingNSEC(t *testing.T) {
	h := nsecZone(t)
	m := h.q("b.example.com.", dns.TypeAAAA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 0 {
		t.Fatalf("NODATA carries answers: %v", m.Answer)
	}
	wantSOAInAuthority(t, m, zoneName)
	got := nsecsByOwner(m)
	if len(got) != 1 {
		t.Fatalf("want exactly the matching NSEC, got %v", m.Ns)
	}
	wantNSEC(t, got, "b.example.com.", "a.z.example.com.", dns.TypeA, dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC)
	verifyEveryRRset(t, m, m.Ns, h.signer.DNSKEYs(zoneName))
}

func TestSignedZoneNODATAAtTheApexListsTheKeyTypes(t *testing.T) {
	h := nsecZone(t)
	m := h.q("example.com.", dns.TypeTXT, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	wantNSEC(t, nsecsByOwner(m), "example.com.", "b.example.com.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY)
	verifyEveryRRset(t, m, m.Ns, h.signer.DNSKEYs(zoneName))
}

func TestSignedZoneNODATAForAnEmptyNonTerminalIsNotNXDOMAIN(t *testing.T) {
	h := nsecZone(t)
	m := h.q("z.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	got := nsecsByOwner(m)
	if len(got) != 1 {
		t.Fatalf("want 1 covering NSEC, got %v", m.Ns)
	}
	// The NSEC covering the empty non-terminal ends at a name below it.
	wantNSEC(t, got, "b.example.com.", "a.z.example.com.", dns.TypeA, dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC)
	verifyEveryRRset(t, m, m.Ns, h.signer.DNSKEYs(zoneName))
}

func TestNSECDenialHasNoSignatureWithoutDNSSECOK(t *testing.T) {
	h := nsecZone(t)
	for _, name := range []string{"m.example.com.", "b.example.com."} {
		m := h.q(name, dns.TypeAAAA)
		if len(rrsOfType(m.Ns, dns.TypeNSEC))+len(rrsOfType(m.Ns, dns.TypeRRSIG)) != 0 {
			t.Fatalf("%s: denial records without DO: %v", name, m.Ns)
		}
	}
}

// The name list that builds the chain follows the view the client is in.
func TestNSECBitmapDoesNotListTypesOnlyAnotherViewHas(t *testing.T) {
	h := newHarness(t, withSigner(), withViews(map[string][]string{"internal": {"10.0.0.0/8"}}))
	h.addZone(zoneName,
		rec("www.example.com.", dns.TypeA, "192.0.2.1"),
	)
	r := rec("www.example.com.", dns.TypeAAAA, "2001:db8::1")
	r.View = "internal"
	h.auth.AddRecord(zoneName, r)
	m := h.ask("203.0.113.9", "www.example.com.", dns.TypeAAAA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	wantNSEC(t, nsecsByOwner(m), "www.example.com.", "example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)
}
