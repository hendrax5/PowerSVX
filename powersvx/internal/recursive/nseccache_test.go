package recursive

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNSECAggressiveCover(t *testing.T) {
	c := newNSECCache()
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Ttl: 300},
		NextDomain: "c.example.com.",
		TypeBitMap: []uint16{dns.TypeA},
	}
	c.addFrom([]dns.RR{n})

	if c.cover("b.example.com.") == nil {
		t.Fatal("b is inside the proven gap (a,c); should synthesize NXDOMAIN")
	}
	if c.cover("z.example.com.") != nil {
		t.Fatal("z is outside the gap; must not be covered")
	}
	if c.cover("a.example.com.") != nil {
		t.Fatal("exact owner exists; must not be covered")
	}
}

func TestNSECCacheExpiry(t *testing.T) {
	c := newNSECCache()
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Ttl: 0},
		NextDomain: "c.example.com.",
	}
	c.addFrom([]dns.RR{n})
	if c.cover("b.example.com.") != nil {
		t.Fatal("ttl=0 NSEC must expire immediately")
	}
}
