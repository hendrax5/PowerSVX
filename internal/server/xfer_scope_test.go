package server

// A transfer carries only what the primary would answer to the requesting
// address (ticket #67): its split-horizon view and its GeoDNS answer, for signed
// and unsigned zones, AXFR and the whole-zone answer to IXFR.

import (
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
)

const (
	scopeInternalIP = "10.1.1.1"
	scopeGermanIP   = "203.0.113.77"
	scopeOtherIP    = "198.51.100.9"
)

func scopeOptions() []option {
	return []option{
		withViews(map[string][]string{"internal": {"10.0.0.0/8"}}),
		withGeo(map[string]string{scopeGermanIP: "DE"}),
	}
}

func addScopeRecords(h *harness, zone string) {
	h.auth.UpsertZone(zone)
	h.auth.AddRecord(zone, authoritative.Record{Name: zone, Type: dns.TypeSOA, TTL: 300, Content: "ns1." + zone + " hostmaster." + zone + " 10 3600 600 86400 300"})
	h.auth.AddRecord(zone, rec(zone, dns.TypeNS, "ns1."+zone))
	h.auth.AddRecord(zone, rec("ns1."+zone, dns.TypeA, "192.0.2.53"))
	h.auth.AddRecord(zone, rec("www."+zone, dns.TypeA, "192.0.2.10"))
	h.auth.AddRecord(zone, authoritative.Record{Name: "app." + zone, Type: dns.TypeA, TTL: 300, Content: "10.0.0.5", View: "internal"})
	h.auth.AddRecord(zone, authoritative.Record{Name: "only-internal." + zone, Type: dns.TypeA, TTL: 300, Content: "10.0.0.6", View: "internal"})
	h.auth.AddRecord(zone, authoritative.Record{Name: "app." + zone, Type: dns.TypeA, TTL: 300, Content: "192.0.2.5", View: "default"})
	h.auth.AddRecord(zone, authoritative.Record{Name: "geo." + zone, Type: dns.TypeA, TTL: 300, Content: "192.0.2.80"})
	h.auth.AddRecord(zone, authoritative.Record{Name: "geo." + zone, Type: dns.TypeA, TTL: 300, Content: "192.0.2.81", GeoTag: "DE"})
}

// dataSet lists the A/NS/SOA data of a transfer as "name type content", sorted,
// with the framing SOA counted separately.
func dataSet(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.Hdr.Name+" A "+v.A.String())
		case *dns.NS:
			out = append(out, v.Hdr.Name+" NS "+v.Ns)
		}
	}
	sort.Strings(out)
	return out
}

func wantScope(t *testing.T, label string, rrs []dns.RR, want ...string) {
	t.Helper()
	wantSOAFirstAndLast(t, rrs)
	sort.Strings(want)
	if got := dataSet(rrs); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("%s: transfer holds\n  %v\nwant\n  %v", label, got, want)
	}
	if n := len(rrsOfType(rrs, dns.TypeSOA)); n != 2 {
		t.Fatalf("%s: %d SOA records, want the framing pair", label, n)
	}
}

func scopeCases(zone string) []struct {
	name, ip string
	want     []string
} {
	ns := []string{zone + " NS ns1." + zone, "ns1." + zone + " A 192.0.2.53"}
	with := func(extra ...string) []string { return append(append([]string{}, ns...), extra...) }
	return []struct {
		name, ip string
		want     []string
	}{
		{"internal view", scopeInternalIP, with("www."+zone+" A 192.0.2.10", "app."+zone+" A 10.0.0.5", "only-internal."+zone+" A 10.0.0.6", "geo."+zone+" A 192.0.2.80")},
		{"no view", scopeOtherIP, with("www."+zone+" A 192.0.2.10", "app."+zone+" A 192.0.2.5", "geo."+zone+" A 192.0.2.80")},
		{"geo override", scopeGermanIP, with("www."+zone+" A 192.0.2.10", "app."+zone+" A 192.0.2.5", "geo."+zone+" A 192.0.2.81")},
	}
}

func TestUnsignedZoneTransferCarriesOnlyTheAnswerForTheRequestingAddress(t *testing.T) {
	h := newHarness(t, append([]option{withConfig(allowTransfer)}, scopeOptions()...)...)
	addScopeRecords(h, zoneName)
	for _, c := range scopeCases(zoneName) {
		rrs, _ := h.transfer(newWriter(c.ip), zoneName, dns.TypeAXFR, 0)
		wantScope(t, "AXFR "+c.name, rrs, c.want...)
	}
}

func TestUnsignedZoneIXFRIsTheWholeScopedZoneNeverADeltaWithOtherViews(t *testing.T) {
	h := newHarness(t, append([]option{withConfig(allowTransfer)}, scopeOptions()...)...)
	addScopeRecords(h, zoneName)
	start := h.auth.CurrentSOASerial(zoneName)
	h.auth.AddRecord(zoneName, authoritative.Record{Name: "secret." + zoneName, Type: dns.TypeA, TTL: 300, Content: "10.0.0.99", View: "internal"})
	h.auth.AddRecord(zoneName, rec("pub."+zoneName, dns.TypeA, "192.0.2.99"))
	end := h.auth.CurrentSOASerial(zoneName)

	rrs, _ := h.transfer(newWriter(scopeOtherIP), zoneName, dns.TypeIXFR, start)
	wantSOAFirstAndLast(t, rrs)
	if serials := soaSerials(rrs); len(serials) != 2 || serials[0] != end || serials[1] != end {
		t.Fatalf("an IXFR is a whole-zone answer, got SOA serials %v", serials)
	}
	got := strings.Join(dataSet(rrs), "|")
	if strings.Contains(got, "10.0.0.") || !strings.Contains(got, "pub."+zoneName+" A 192.0.2.99") || !strings.Contains(got, "www."+zoneName) {
		t.Fatalf("IXFR to an address in no view holds %v", dataSet(rrs))
	}

	rrs, _ = h.transfer(newWriter(scopeInternalIP), zoneName, dns.TypeIXFR, start)
	if got := strings.Join(dataSet(rrs), "|"); !strings.Contains(got, "secret."+zoneName+" A 10.0.0.99") || strings.Contains(got, "app."+zoneName+" A 192.0.2.5") {
		t.Fatalf("IXFR to the internal view holds %v", dataSet(rrs))
	}

	rrs, _ = h.transfer(newWriter(scopeOtherIP), zoneName, dns.TypeIXFR, end)
	if len(rrs) != 1 || rrs[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("a current client gets only the SOA, got %v", rrs)
	}
}

func TestSignedZoneTransferCarriesOnlyTheAnswerForTheRequestingAddress(t *testing.T) {
	h := newHarness(t, append([]option{withConfig(allowTransfer), withSigner()}, scopeOptions()...)...)
	addScopeRecords(h, zoneName)
	signZone(t, h)
	for _, c := range scopeCases(zoneName) {
		rrs, _ := h.transfer(newWriter(c.ip), zoneName, dns.TypeAXFR, 0)
		wantScope(t, "signed AXFR "+c.name, rrs, c.want...)
		verifyTransfer(t, h, rrs)
		start := uint32(1)
		rrs, _ = h.transfer(newWriter(c.ip), zoneName, dns.TypeIXFR, start)
		wantScope(t, "signed IXFR "+c.name, rrs, c.want...)
		verifyTransfer(t, h, rrs)
	}
}

func TestTransferAccessRulesStillApplyToUnsignedViewedZones(t *testing.T) {
	t.Run("outside the allow list", func(t *testing.T) {
		h := newHarness(t, append([]option{withConfig(func(c *config.Config) {
			allowTransfer(c)
			c.Transfer.AllowFrom = []string{"10.0.0.0/8"}
		})}, scopeOptions()...)...)
		addScopeRecords(h, zoneName)
		_, msgs := h.transfer(newWriter(scopeOtherIP), zoneName, dns.TypeAXFR, 0)
		if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused || len(msgs[0].Answer) != 0 {
			t.Fatalf("want a lone REFUSED, got %v", msgs)
		}
		rrs, _ := h.transfer(newWriter(scopeInternalIP), zoneName, dns.TypeAXFR, 0)
		wantSOAFirstAndLast(t, rrs)
	})
	t.Run("TSIG required", func(t *testing.T) {
		h := newHarness(t, append([]option{withConfig(func(c *config.Config) { c.Transfer.AllowAXFR, c.Transfer.RequireTSIG = true, true })}, scopeOptions()...)...)
		addScopeRecords(h, zoneName)
		_, msgs := h.transfer(newWriter(scopeInternalIP), zoneName, dns.TypeAXFR, 0)
		if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused || len(msgs[0].Answer) != 0 {
			t.Fatalf("want a lone REFUSED without TSIG, got %v", msgs)
		}
	})
	t.Run("transfers off", func(t *testing.T) {
		h := newHarness(t, append([]option{withConfig(func(c *config.Config) { c.Transfer.AllowAXFR = false })}, scopeOptions()...)...)
		addScopeRecords(h, zoneName)
		_, msgs := h.transfer(newWriter(scopeInternalIP), zoneName, dns.TypeAXFR, 0)
		if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
			t.Fatalf("want REFUSED, got %v", msgs)
		}
	})
}

func signZone(t *testing.T, h *harness) {
	t.Helper()
	if err := h.signer.EnsureWithOptions(zoneName, dnssec.SignOptions{Algorithm: dns.ECDSAP256SHA256}); err != nil {
		t.Fatal(err)
	}
}
