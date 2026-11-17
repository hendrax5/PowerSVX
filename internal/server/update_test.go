package server

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
)

func TestApplyUpdateAddAndDelete(t *testing.T) {
	auth := authoritative.NewStore()
	auth.UpsertZone("example.com.")
	auth.AddRecord("example.com.", authoritative.Record{
		Name: "example.com.", Type: dns.TypeSOA, TTL: 60,
		Content: "ns.example.com. hostmaster.example.com. 1 3600 600 86400 60",
	})

	add, err := dns.NewRR("www.example.com. 300 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if rc := applyUpdateSection(auth, "example.com.", []dns.RR{add}); rc != dns.RcodeSuccess {
		t.Fatalf("add rc=%d", rc)
	}
	if !auth.RRSetExists("example.com.", "www.example.com.", dns.TypeA) {
		t.Fatal("A missing after add")
	}
	if got := auth.CurrentSOASerial("example.com."); got != 2 {
		t.Fatalf("serial after update=%d want 2", got)
	}
	serial, ok := auth.BumpSOASerial("example.com.")
	if !ok || serial != 3 {
		t.Fatalf("serial=%d ok=%v", serial, ok)
	}

	del := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassNONE, Ttl: 0},
		A:   netA("192.0.2.1"),
	}
	if rc := applyUpdateSection(auth, "example.com.", []dns.RR{del}); rc != dns.RcodeSuccess {
		t.Fatalf("del rc=%d", rc)
	}
	if auth.RRSetExists("example.com.", "www.example.com.", dns.TypeA) {
		t.Fatal("A should be gone")
	}
}

func netA(s string) []byte {
	rr, _ := dns.NewRR("x. 0 IN A " + s)
	return rr.(*dns.A).A
}

func TestUpdatePolicyAllows(t *testing.T) {
	pols := []config.UpdatePolicyTOML{
		{Key: "key.example.com.", Zones: []string{"example.com"}},
	}
	if !updatePolicyAllows(pols, "key.example.com.", "example.com.") {
		t.Fatal("expected allow")
	}
	if updatePolicyAllows(pols, "key.example.com.", "other.com.") {
		t.Fatal("expected deny other zone")
	}
	if updatePolicyAllows(nil, "", "example.com.") {
		// empty policies always allow
	} else {
		t.Fatal("empty policies should allow")
	}
}

func TestCheckUpdatePrereqNXRRSet(t *testing.T) {
	auth := authoritative.NewStore()
	auth.UpsertZone("example.com.")
	prereq := &dns.RR_Header{Name: "missing.example.com.", Rrtype: dns.TypeA, Class: dns.ClassANY, Ttl: 0}
	rc := checkUpdatePrereqs(auth, "example.com.", []dns.RR{&dns.A{Hdr: *prereq}})
	if rc != dns.RcodeNXRrset {
		t.Fatalf("rc=%d", rc)
	}
}
