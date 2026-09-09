package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNSECAggressiveCover(t *testing.T) {
	c := NewNSECCache()
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Ttl: 300},
		NextDomain: "c.example.com.",
		TypeBitMap: []uint16{dns.TypeA},
	}
	c.AddFrom([]dns.RR{n})

	if c.Cover("b.example.com.") == nil {
		t.Fatal("b is inside the proven gap (a,c); should synthesize NXDOMAIN")
	}
	if c.Cover("z.example.com.") != nil {
		t.Fatal("z is outside the gap; must not be covered")
	}
	if c.Cover("a.example.com.") != nil {
		t.Fatal("exact owner exists; must not be covered")
	}
}

func TestNSECCacheExpiry(t *testing.T) {
	c := NewNSECCache()
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Ttl: 0},
		NextDomain: "c.example.com.",
	}
	c.AddFrom([]dns.RR{n})
	if c.Cover("b.example.com.") != nil {
		t.Fatal("ttl=0 NSEC must expire immediately")
	}
}

func TestNSECTLDApexDoesNotCoverChildren(t *testing.T) {
	c := NewNSECCache()
	c.AddFrom([]dns.RR{&dns.NSEC{
		Hdr:        dns.RR_Header{Name: "com.", Rrtype: dns.TypeNSEC, Ttl: 86400},
		NextDomain: "commbank.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC},
	}})
	if c.Cover("google.com.") != nil {
		t.Fatal("TLD-apex NSEC must not synthesize NXDOMAIN for google.com")
	}
	if c.Cover("example.com.") != nil {
		t.Fatal("TLD-apex NSEC must not cover example.com")
	}
	c.AddFrom([]dns.RR{&dns.NSEC{
		Hdr:        dns.RR_Header{Name: "id.", Rrtype: dns.TypeNSEC, Ttl: 86400},
		NextDomain: "info.",
	}})
	if c.Cover("go.id.") != nil || c.Cover("putatgede.kendalkab.go.id.") != nil {
		t.Fatal("TLD-apex NSEC must not NXDOMAIN government/ccTLD children")
	}
}

func TestNSECCoverWraparound(t *testing.T) {
	c := NewNSECCache()
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "z.example.com.", Rrtype: dns.TypeNSEC, Ttl: 300},
		NextDomain: "a.example.com.",
	}
	c.AddFrom([]dns.RR{n})
	if c.Cover("zz.example.com.") == nil {
		t.Fatal("zz should be in wraparound gap after z")
	}
	if c.Cover("b.example.com.") != nil {
		t.Fatal("b sits after next=a; wraparound must not cover it")
	}
}

func TestNSECCoverIgnoresNSEC3(t *testing.T) {
	c := NewNSECCache()
	n3 := &dns.NSEC3{
		Hdr: dns.RR_Header{Name: "hash.example.com.", Rrtype: dns.TypeNSEC3, Ttl: 300},
	}
	c.AddFrom([]dns.RR{n3})
	if c.Cover("b.example.com.") != nil {
		t.Fatal("NSEC3 must not be used for aggressive answering")
	}
}
