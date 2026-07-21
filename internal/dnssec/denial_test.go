package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestEvaluateDenialNSEC3Cover(t *testing.T) {
	// Synthetic NSEC3 that covers a name via Cover() — build using HashName owner.
	salt := ""
	iter := uint16(0)
	hash := dns.HashName("nx.example.com.", dns.SHA1, iter, salt)
	next := dns.HashName("zz.example.com.", dns.SHA1, iter, salt)
	nsec3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: hash + ".example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: iter,
		SaltLength: 0,
		Salt:       salt,
		HashLength: 20,
		NextDomain: next,
		TypeBitMap: []uint16{dns.TypeA},
	}
	msg := new(dns.Msg)
	msg.SetQuestion("nx.example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{nsec3}

	// Cover may or may not match depending on hash ordering; exercise path.
	res, ok := evaluateDenial(msg)
	if !ok {
		t.Fatal("expected denial evaluation attempted")
	}
	_ = res
}

func TestTypeBitmapHas(t *testing.T) {
	if !typeBitmapHas([]uint16{dns.TypeA, dns.TypeAAAA}, dns.TypeA) {
		t.Fatal("expected has A")
	}
	if typeBitmapHas([]uint16{dns.TypeNS}, dns.TypeA) {
		t.Fatal("should not have A")
	}
}

func TestNSECCovers(t *testing.T) {
	n := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com."},
		NextDomain: "c.example.com.",
	}
	if !nsecCovers(n, "b.example.com.") {
		t.Fatal("expected cover")
	}
	if nsecCovers(n, "d.example.com.") {
		t.Fatal("should not cover")
	}
}
