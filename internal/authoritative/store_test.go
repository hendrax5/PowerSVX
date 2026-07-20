package authoritative

import (
	"testing"

	"github.com/miekg/dns"
)

func TestLookupScopedViewAndGeo(t *testing.T) {
	s := NewStore()
	s.Replace(map[string][]Record{
		"example.com.": {
			{Name: "www.example.com.", Type: dns.TypeA, Content: "10.0.0.1", View: "internal", GeoTag: ""},
			{Name: "www.example.com.", Type: dns.TypeA, Content: "1.2.3.4", View: "default", GeoTag: "DEFAULT"},
			{Name: "cdn.example.com.", Type: dns.TypeA, Content: "103.0.0.1", View: "", GeoTag: "ID"},
			{Name: "cdn.example.com.", Type: dns.TypeA, Content: "8.8.8.8", View: "", GeoTag: "DEFAULT"},
		},
	})

	rrs, ok := s.LookupScoped("www.example.com.", dns.TypeA, "internal", "ID")
	if !ok || len(rrs) != 1 {
		t.Fatalf("internal: %v %d", ok, len(rrs))
	}
	if a := rrs[0].(*dns.A).A.String(); a != "10.0.0.1" {
		t.Fatal(a)
	}

	rrs, _ = s.LookupScoped("cdn.example.com.", dns.TypeA, "default", "ID")
	if len(rrs) != 1 || rrs[0].(*dns.A).A.String() != "103.0.0.1" {
		t.Fatalf("geo ID: %+v", rrs)
	}
	rrs, _ = s.LookupScoped("cdn.example.com.", dns.TypeA, "default", "US")
	if len(rrs) != 1 || rrs[0].(*dns.A).A.String() != "8.8.8.8" {
		t.Fatalf("geo default: %+v", rrs)
	}
}
