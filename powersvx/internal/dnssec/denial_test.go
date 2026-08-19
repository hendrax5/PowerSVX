package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestProveNSEC_NODATA(t *testing.T) {
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC},
		NextDomain: "z.example.test.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	// AAAA is absent from the bitmap => NODATA proven.
	if !proveNSEC([]*dns.NSEC{n}, "example.test.", dns.TypeAAAA, false) {
		t.Fatal("expected NODATA proof for AAAA")
	}
	// A is present => must NOT prove NODATA for A.
	if proveNSEC([]*dns.NSEC{n}, "example.test.", dns.TypeA, false) {
		t.Fatal("A exists; NODATA must not be proven")
	}
}

func TestProveNSEC_NXDOMAIN(t *testing.T) {
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.test.", Rrtype: dns.TypeNSEC},
		NextDomain: "c.example.test.",
		TypeBitMap: []uint16{dns.TypeA},
	}
	if !proveNSEC([]*dns.NSEC{n}, "b.example.test.", dns.TypeA, true) {
		t.Fatal("b is in gap (a,c); should be covered")
	}
	if proveNSEC([]*dns.NSEC{n}, "d.example.test.", dns.TypeA, true) {
		t.Fatal("d is outside the gap; must not be covered")
	}
}

func TestNSECCoversOrdering(t *testing.T) {
	if !nsecCovers("a.x.", "c.x.", "b.x.") {
		t.Error("b.x. should be covered by (a.x., c.x.)")
	}
	if nsecCovers("a.x.", "c.x.", "a.x.") {
		t.Error("exact owner is not covered")
	}
	// Wraparound: last NSEC where next is the apex.
	if !nsecCovers("z.x.", "x.", "zz.x.") {
		t.Error("zz.x. should be covered by wraparound NSEC")
	}
}

func TestTypeInBitmap(t *testing.T) {
	b := []uint16{dns.TypeA, dns.TypeMX}
	if !typeInBitmap(b, dns.TypeMX) || typeInBitmap(b, dns.TypeAAAA) {
		t.Error("bitmap membership wrong")
	}
}
