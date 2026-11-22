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

func TestBuildRRTypesAndBINDImportExport(t *testing.T) {
	// IPv4 vs IPv6 strict check
	if err := ValidateRecord(Record{Name: "a.example.com.", Type: dns.TypeA, Content: "2001:db8::1"}); err == nil {
		t.Fatal("expected error passing IPv6 to A record")
	}
	if err := ValidateRecord(Record{Name: "a.example.com.", Type: dns.TypeAAAA, Content: "1.2.3.4"}); err == nil {
		t.Fatal("expected error passing IPv4 to AAAA record")
	}
	// CAA TTL preservation
	rr := RecordToRR(Record{Name: "example.com.", Type: dns.TypeCAA, Content: `0 issue "letsencrypt.org"`, TTL: 600})
	if rr == nil || rr.Header().Ttl != 600 {
		t.Fatalf("expected CAA TTL 600, got %+v", rr)
	}
	// BIND import & export
	master := `
$TTL 300
@   IN  SOA ns1.example.com. admin.example.com. 10 3600 600 86400 300
@   IN  NS  ns1.example.com.
www IN  A   203.0.113.10
`
	recs, err := ImportBINDZone("example.com.", master)
	if err != nil || len(recs) != 3 {
		t.Fatalf("ImportBINDZone got len=%d err=%v", len(recs), err)
	}
	s := NewStore()
	s.ReplaceZoneRecords("example.com.", recs)
	s.AddRecord("example.com.", Record{Name: "api.example.com.", Type: dns.TypeA, Content: "203.0.113.20", TTL: 120})
	deltas, cur, ok := s.IXFRDeltas("example.com.", 10)
	if !ok || cur != 11 || len(deltas) != 1 || len(deltas[0].Added) != 1 {
		t.Fatalf("IXFRDeltas failed: ok=%v cur=%d deltas=%+v", ok, cur, deltas)
	}
	exported, ok := s.ExportBINDZone("example.com.")
	if !ok || exported == "" {
		t.Fatal("ExportBINDZone failed")
	}
}

func TestFindZoneMatchesOnLabelBoundaries(t *testing.T) {
	s := NewStore()
	s.Replace(map[string][]Record{
		"example.com.":     {{Name: "www.example.com.", Type: dns.TypeA, Content: "192.0.2.1"}},
		"sub.example.com.": {{Name: "www.sub.example.com.", Type: dns.TypeA, Content: "192.0.2.2"}},
	})
	cases := map[string]string{
		"example.com.":          "example.com.",
		"www.example.com.":      "example.com.",
		"a.b.example.com.":      "example.com.",
		"www.sub.example.com.":  "sub.example.com.",
		"badexample.com.":       "",
		"www.badexample.com.":   "",
		"notsub.example.com.":   "example.com.",
		"xsub.example.com.":     "example.com.",
		"example.com.evil.net.": "",
		"com.":                  "",
	}
	for q, want := range cases {
		if got := s.FindZone(q); got != want {
			t.Errorf("FindZone(%q)=%q want %q", q, got, want)
		}
	}
	if _, in := s.LookupScoped("badexample.com.", dns.TypeA, "", ""); in {
		t.Error("badexample.com. reported as inside example.com.")
	}
}
