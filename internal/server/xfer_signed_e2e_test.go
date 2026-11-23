package server

// Transfers of signed zones (docs/adr/0004): what AXFR and IXFR carry, how the
// serial follows the signatures, and a Secondary Zone serving what it received.
// The independent validator (delv against a BIND secondary) is test/xfersigned.

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/secondary"
)

// signedPrimary is a primary that offers transfers and signs example.com. with
// NSEC or NSEC3. z.example.com. is an empty non-terminal; w and c hold wildcards.
func signedPrimary(t *testing.T, nsec3 bool, opts ...option) *harness {
	t.Helper()
	h := newHarness(t, append([]option{withConfig(allowTransfer), withSigner()}, opts...)...)
	h.auth.UpsertZone(zoneName)
	h.auth.AddRecord(zoneName, authoritative.Record{Name: zoneName, Type: dns.TypeSOA, TTL: 300, Content: soaContent})
	for _, r := range []authoritative.Record{
		rec(zoneName, dns.TypeNS, "ns1.example.com."),
		rec("ns1.example.com.", dns.TypeA, "192.0.2.53"),
		rec("www.example.com.", dns.TypeA, "192.0.2.10"),
		rec("www.example.com.", dns.TypeTXT, "hello"),
		rec("b.example.com.", dns.TypeA, "192.0.2.11"),
		rec("a.z.example.com.", dns.TypeAAAA, "2001:db8::1"),
		rec("*.w.example.com.", dns.TypeA, "192.0.2.77"),
		rec("*.c.example.com.", dns.TypeCNAME, "www.example.com."),
	} {
		h.auth.AddRecord(zoneName, r)
	}
	if err := h.signer.EnsureWithOptions(zoneName, dnssec.SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: nsec3}); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) axfr(t *testing.T) []dns.RR {
	t.Helper()
	rrs, msgs := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeAXFR, 0)
	if len(msgs) == 1 && msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("AXFR answered %s", dns.RcodeToString[msgs[0].Rcode])
	}
	return rrs
}

func typesIn(rrs []dns.RR) map[uint16]int {
	out := map[uint16]int{}
	for _, rr := range rrs {
		out[rr.Header().Rrtype]++
	}
	return out
}

func wantSOAFirstAndLast(t *testing.T, rrs []dns.RR) {
	t.Helper()
	if len(rrs) < 3 {
		t.Fatalf("transfer too short: %v", rrs)
	}
	first, ok1 := rrs[0].(*dns.SOA)
	last, ok2 := rrs[len(rrs)-1].(*dns.SOA)
	if !ok1 || !ok2 || first.Serial != last.Serial {
		t.Fatalf("transfer must start and end with the same SOA, got %T and %T", rrs[0], rrs[len(rrs)-1])
	}
}

// verifyTransfer checks every RRset of a transfer against the zone keys.
func verifyTransfer(t *testing.T, h *harness, rrs []dns.RR) {
	t.Helper()
	verifyEveryRRset(t, &dns.Msg{Answer: rrs}, rrs, h.signer.DNSKEYs(zoneName))
}

func dataOwners(rrs []dns.RR) map[string]bool {
	out := map[string]bool{}
	for _, rr := range rrs {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
		default:
			out[dns.CanonicalName(rr.Header().Name)] = true
		}
	}
	return out
}

func TestAXFROfAnNSECSignedZoneCarriesTheKeysTheSignaturesAndTheChain(t *testing.T) {
	h := signedPrimary(t, false)
	rrs := h.axfr(t)
	wantSOAFirstAndLast(t, rrs)
	types := typesIn(rrs)
	if types[dns.TypeDNSKEY] != 2 {
		t.Fatalf("want the ZSK and KSK, got %d DNSKEY", types[dns.TypeDNSKEY])
	}
	if types[dns.TypeNSEC3] != 0 || types[dns.TypeNSEC3PARAM] != 0 {
		t.Fatal("NSEC zone carries NSEC3 records")
	}
	verifyTransfer(t, h, rrs)

	// The chain closes on itself and has one record for each name that owns data.
	next := map[string]string{}
	for _, rr := range rrsOfType(rrs, dns.TypeNSEC) {
		n := rr.(*dns.NSEC)
		next[dns.CanonicalName(n.Hdr.Name)] = dns.CanonicalName(n.NextDomain)
		if n.Hdr.Ttl != 300 {
			t.Errorf("NSEC TTL %d, want the SOA minimum 300", n.Hdr.Ttl)
		}
	}
	owners := dataOwners(rrs)
	if len(next) != len(owners) {
		t.Fatalf("%d NSEC for %d names", len(next), len(owners))
	}
	seen, cur := 0, zoneName
	for {
		nx, ok := next[cur]
		if !ok || !owners[cur] {
			t.Fatalf("chain broken at %s", cur)
		}
		seen++
		cur = nx
		if cur == zoneName {
			break
		}
		if seen > len(owners) {
			t.Fatal("chain does not return to the apex")
		}
	}
	if seen != len(owners) {
		t.Fatalf("chain visits %d of %d names", seen, len(owners))
	}
}

func TestAXFROfAnNSEC3SignedZoneCarriesTheChainAndASignedNSEC3PARAM(t *testing.T) {
	h := signedPrimary(t, true)
	rrs := h.axfr(t)
	wantSOAFirstAndLast(t, rrs)
	types := typesIn(rrs)
	if types[dns.TypeNSEC] != 0 {
		t.Fatal("NSEC3 zone carries NSEC records")
	}
	if types[dns.TypeNSEC3PARAM] != 1 {
		t.Fatalf("want one NSEC3PARAM, got %d", types[dns.TypeNSEC3PARAM])
	}
	wantNSEC3PARAMMatchesPolicy(t, h, nsec3paramOf(rrs))
	verifyTransfer(t, h, rrs) // includes the RRSIG over NSEC3PARAM

	salt := h.nsec3Salt()
	// Names with data, plus the empty non-terminals z, w and c.
	want := map[string]bool{}
	for o := range dataOwners(rrs) {
		want[strings.ToUpper(dns.HashName(o, dns.SHA1, 1, salt))] = true
	}
	for _, ent := range []string{"z.example.com.", "w.example.com.", "c.example.com."} {
		want[strings.ToUpper(dns.HashName(ent, dns.SHA1, 1, salt))] = true
	}
	next := map[string]string{}
	for _, rr := range rrsOfType(rrs, dns.TypeNSEC3) {
		n := rr.(*dns.NSEC3)
		label := strings.ToUpper(strings.SplitN(n.Hdr.Name, ".", 2)[0])
		next[label] = strings.ToUpper(n.NextDomain)
		if !want[label] {
			t.Errorf("NSEC3 %s belongs to no name of the zone", label)
		}
	}
	if len(next) != len(want) {
		t.Fatalf("%d NSEC3 for %d names", len(next), len(want))
	}
	hashes := make([]string, 0, len(next))
	for h := range next {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	for i, h := range hashes {
		if next[h] != hashes[(i+1)%len(hashes)] {
			t.Errorf("NSEC3 %s points to %s, want %s", h, next[h], hashes[(i+1)%len(hashes)])
		}
	}
}

func TestAXFROfAnUnsignedZoneHasNoDNSSECRecordsEvenWhenTheProcessSignsOtherZones(t *testing.T) {
	h := signedPrimary(t, false)
	h.auth.UpsertZone("plain.test.")
	h.auth.AddRecord("plain.test.", authoritative.Record{Name: "plain.test.", Type: dns.TypeSOA, TTL: 300, Content: "ns1.plain.test. h.plain.test. 1 3600 600 86400 300"})
	h.auth.AddRecord("plain.test.", rec("www.plain.test.", dns.TypeA, "192.0.2.20"))
	rrs, _ := h.transfer(newWriter(anyClientIP), "plain.test.", dns.TypeAXFR, 0)
	wantSOAFirstAndLast(t, rrs)
	if len(rrs) != 3 {
		t.Fatalf("want SOA, A, SOA; got %v", rrs)
	}
}

func TestSignedTransferKeepsSigningKeysOut(t *testing.T) {
	h := signedPrimary(t, true)
	for _, rr := range h.axfr(t) {
		switch rr.Header().Rrtype {
		case dns.TypeSOA, dns.TypeNS, dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeCNAME,
			dns.TypeDNSKEY, dns.TypeRRSIG, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
		default:
			t.Errorf("unexpected record in a transfer: %v", rr)
		}
		if strings.Contains(rr.String(), "PrivateKey") || strings.Contains(rr.String(), "Private-key-format") {
			t.Fatalf("private key material in a transfer: %v", rr)
		}
	}
}

func TestSignedTransferSignaturesMatchWhatQueriesAreAnsweredWith(t *testing.T) {
	h := signedPrimary(t, false)
	rrs := h.axfr(t)
	m := h.q("www.example.com.", dns.TypeA, withDO())
	var qsig, xsig *dns.RRSIG
	for _, rr := range rrsOfType(m.Answer, dns.TypeRRSIG) {
		qsig = rr.(*dns.RRSIG)
	}
	for _, rr := range rrsOfType(rrs, dns.TypeRRSIG) {
		if s := rr.(*dns.RRSIG); s.TypeCovered == dns.TypeA && dns.CanonicalName(s.Hdr.Name) == "www.example.com." {
			xsig = s
		}
	}
	if qsig == nil || xsig == nil {
		t.Fatal("missing RRSIG")
	}
	if qsig.KeyTag != xsig.KeyTag || qsig.Algorithm != xsig.Algorithm || qsig.Labels != xsig.Labels || qsig.OrigTtl != xsig.OrigTtl || qsig.SignerName != xsig.SignerName {
		t.Fatalf("query RRSIG %v and transfer RRSIG %v differ in more than the window", qsig, xsig)
	}
}

func TestSignedTransferSignaturesStayValidForLongerThanTheRefreshInterval(t *testing.T) {
	h := signedPrimary(t, false)
	h.cfg.Transfer.SignatureValidityDays = 20
	h.cfg.Transfer.SignatureRefreshDays = 5
	rrs := h.axfr(t)
	now := time.Now()
	for _, rr := range rrsOfType(rrs, dns.TypeRRSIG) {
		s := rr.(*dns.RRSIG)
		exp := time.Unix(int64(s.Expiration), 0)
		if !s.ValidityPeriod(now) {
			t.Errorf("RRSIG not valid now: %v", s)
		}
		if exp.Sub(now) < 15*24*time.Hour-time.Minute {
			t.Errorf("RRSIG expires in %v, want at least validity minus refresh (15 days)", exp.Sub(now))
		}
		if exp.Sub(now) > 20*24*time.Hour {
			t.Errorf("RRSIG expires in %v, more than the configured validity", exp.Sub(now))
		}
	}
}

func TestSignedZoneIXFRSendsTheWholeZoneAndASingleSOAWhenTheClientIsCurrent(t *testing.T) {
	h := signedPrimary(t, false)
	start := h.auth.CurrentSOASerial(zoneName)
	h.auth.AddRecord(zoneName, rec("new.example.com.", dns.TypeA, "192.0.2.55"))
	end := h.auth.CurrentSOASerial(zoneName)

	rrs, _ := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeIXFR, start)
	wantSOAFirstAndLast(t, rrs)
	if serials := soaSerials(rrs); len(serials) != 2 || serials[0] != end {
		t.Fatalf("an IXFR of a signed zone is a whole-zone answer, got SOA serials %v", serials)
	}
	if _, isSOA := rrs[1].(*dns.SOA); isSOA {
		t.Fatal("IXFR answer looks like a delta")
	}
	if len(rrsOfType(rrs, dns.TypeRRSIG)) == 0 || len(rrsOfType(rrs, dns.TypeNSEC)) == 0 || len(rrsOfType(rrs, dns.TypeDNSKEY)) != 2 {
		t.Fatalf("whole-zone answer lacks DNSSEC records: %v", typesIn(rrs))
	}
	verifyTransfer(t, h, rrs)
	if len(rrsOfType(rrs, dns.TypeA)) != 5 {
		t.Fatalf("new record missing from the answer: %v", rrsOfType(rrs, dns.TypeA))
	}

	rrs, _ = h.transfer(newWriter(anyClientIP), zoneName, dns.TypeIXFR, end)
	if len(rrs) != 1 || rrs[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("a current client gets only the SOA, got %v", rrs)
	}
}

func TestSignedZoneAXFRChangesWhenTheZoneChangesAndStaysValid(t *testing.T) {
	h := signedPrimary(t, true)
	before := h.axfr(t)
	h.auth.AddRecord(zoneName, rec("new.example.com.", dns.TypeA, "192.0.2.55"))
	h.auth.DeleteRecord(zoneName, "b.example.com.", dns.TypeA)
	after := h.axfr(t)
	verifyTransfer(t, h, after)
	if soaSerials(after)[0] <= soaSerials(before)[0] {
		t.Fatal("serial did not advance")
	}
	owners := dataOwners(after)
	if !owners["new.example.com."] || owners["b.example.com."] {
		t.Fatalf("owners after change: %v", owners)
	}
	if len(rrsOfType(after, dns.TypeNSEC3)) != len(rrsOfType(before, dns.TypeNSEC3)) {
		t.Fatal("one name added and one removed: the NSEC3 chain keeps its length")
	}
}

func TestSignedTransferOverTCPIsSplitIntoMessagesThatFit(t *testing.T) {
	h := signedPrimary(t, false)
	for i := 0; i < 1500; i++ {
		h.auth.AddRecord(zoneName, rec(fmt.Sprintf("host%04d.example.com.", i), dns.TypeA, fmt.Sprintf("10.1.%d.%d", i/250, i%250+1)))
	}
	addr := startTCP(t, h.srv, nil)
	rrs, err := pullAXFR(addr, zoneName, "", "")
	if err != nil {
		t.Fatal(err)
	}
	wantSOAFirstAndLast(t, rrs)
	verifyEveryRRset(t, &dns.Msg{}, rrs, h.signer.DNSKEYs(zoneName))
	if got := len(rrsOfType(rrs, dns.TypeA)); got != 1504 {
		t.Fatalf("%d A records, want 1504", got)
	}
}

func TestSignedTransferOverTCPWithTSIGStillWorksAcrossMessages(t *testing.T) {
	h := signedPrimary(t, true)
	h.cfg.Transfer.RequireTSIG = true
	for i := 0; i < 800; i++ {
		h.auth.AddRecord(zoneName, rec(fmt.Sprintf("host%04d.example.com.", i), dns.TypeA, fmt.Sprintf("10.1.%d.%d", i/250, i%250+1)))
	}
	addr := startTCP(t, h.srv, map[string]string{"xfer-key.": tsigSecret})
	rrs, err := pullAXFR(addr, zoneName, "xfer-key.", tsigSecret)
	if err != nil {
		t.Fatal(err)
	}
	wantSOAFirstAndLast(t, rrs)
	verifyEveryRRset(t, &dns.Msg{}, rrs, h.signer.DNSKEYs(zoneName))
}

func TestSignedZoneTransferAccessRulesAreUnchanged(t *testing.T) {
	t.Run("transfers not enabled", func(t *testing.T) {
		h := signedPrimary(t, false, withConfig(func(c *config.Config) { c.Transfer.AllowAXFR = false }))
		_, msgs := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeAXFR, 0)
		if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused || len(msgs[0].Answer) != 0 {
			t.Fatalf("want a lone REFUSED, got %v", msgs)
		}
	})
	t.Run("outside the allow list", func(t *testing.T) {
		h := signedPrimary(t, false, withConfig(func(c *config.Config) { c.Transfer.AllowFrom = []string{"198.51.100.0/24"} }))
		_, msgs := h.transfer(newWriter("203.0.113.50"), zoneName, dns.TypeAXFR, 0)
		if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused || len(msgs[0].Answer) != 0 {
			t.Fatalf("want a lone REFUSED, got %v", msgs)
		}
		rrs, _ := h.transfer(newWriter("198.51.100.7"), zoneName, dns.TypeAXFR, 0)
		verifyTransfer(t, h, rrs)
	})
	t.Run("failed TSIG", func(t *testing.T) {
		h := signedPrimary(t, false, withConfig(func(c *config.Config) { c.Transfer.RequireTSIG = true }))
		w := newWriter(anyClientIP)
		w.tsigErr = dns.ErrSig
		_, msgs := h.transfer(w, zoneName, dns.TypeIXFR, 1)
		if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeNotAuth || len(msgs[0].Answer) != 0 {
			t.Fatalf("want a lone NOTAUTH, got %v", msgs)
		}
	})
}

func TestSignedZoneTransferShowsTheViewOfTheClientOnly(t *testing.T) {
	h := signedPrimary(t, false, withViews(map[string][]string{"internal": {"10.0.0.0/8"}}))
	h.auth.AddRecord(zoneName, authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "10.0.0.5", View: "internal"})
	h.auth.AddRecord(zoneName, authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.5", View: "default"})
	external, _ := h.transfer(newWriter("203.0.113.9"), zoneName, dns.TypeAXFR, 0)
	internal, _ := h.transfer(newWriter("10.1.1.1"), zoneName, dns.TypeAXFR, 0)
	app := func(rrs []dns.RR) []string {
		var out []string
		for _, rr := range rrsOfType(rrs, dns.TypeA) {
			if rr.Header().Name == "app.example.com." {
				out = append(out, rr.(*dns.A).A.String())
			}
		}
		return out
	}
	if got := app(external); len(got) != 1 || got[0] != "192.0.2.5" {
		t.Fatalf("external transfer holds %v", got)
	}
	if got := app(internal); len(got) != 1 || got[0] != "10.0.0.5" {
		t.Fatalf("internal transfer holds %v", got)
	}
	verifyTransfer(t, h, external)
	verifyTransfer(t, h, internal)
}

// ------------------------------------------------ serial and signatures

func TestSignedZoneSerialMovesWhenTheTransferSignaturesChange(t *testing.T) {
	h := signedPrimary(t, false, withConfig(func(c *config.Config) {
		c.Transfer.SignatureValidityDays = 30
		c.Transfer.SignatureRefreshDays = 7
	}))
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	serial := func() uint32 { return h.auth.CurrentSOASerial(zoneName) }

	s0 := serial()
	if got := h.srv.RefreshSignedZones(now); len(got) != 1 || serial() != s0+1 {
		t.Fatalf("a newly signed zone is bumped once, got %v serial %d", got, serial())
	}
	if got := h.srv.RefreshSignedZones(now.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("same interval, nothing to bump, got %v", got)
	}
	if got := h.srv.RefreshSignedZones(now.Add(8 * 24 * time.Hour)); len(got) != 1 || serial() != s0+2 {
		t.Fatalf("a new interval bumps the serial, got %v serial %d", got, serial())
	}
	if err := h.signer.RolloverZSK(zoneName); err != nil {
		t.Fatal(err)
	}
	if got := h.srv.RefreshSignedZones(now.Add(8*24*time.Hour + time.Minute)); len(got) != 1 {
		t.Fatalf("a rolled key bumps the serial, got %v", got)
	}
	if err := h.signer.EnsureWithOptions(zoneName, dnssec.SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: true}); err != nil {
		t.Fatal(err)
	}
	if got := h.srv.RefreshSignedZones(now.Add(8*24*time.Hour + 2*time.Minute)); len(got) != 1 {
		t.Fatalf("a changed NSEC3 policy bumps the serial, got %v", got)
	}
	final := serial()

	// A restart (new Server over the same keys and zones) does not bump again.
	srv2 := New(h.cfg, Deps{Auth: h.auth, Signer: h.signer}, h.srv.log)
	if got := srv2.RefreshSignedZones(now.Add(8*24*time.Hour + 3*time.Minute)); len(got) != 0 || serial() != final {
		t.Fatalf("restart bumped the serial: %v", got)
	}
}

func TestRefreshSkipsZonesThatAreNotSignedHere(t *testing.T) {
	h := signedPrimary(t, false)
	h.auth.UpsertZone("plain.test.")
	h.auth.AddRecord("plain.test.", authoritative.Record{Name: "plain.test.", Type: dns.TypeSOA, TTL: 300, Content: "ns1.plain.test. h.plain.test. 1 3600 600 86400 300"})
	h.srv.RefreshSignedZones(time.Now())
	if got := h.auth.CurrentSOASerial("plain.test."); got != 1 {
		t.Fatalf("unsigned zone serial moved to %d", got)
	}
}

func TestTransferSignatureValidityIsClampedSoARefreshFitsTwiceIntoIt(t *testing.T) {
	p := dnssec.SigPolicy{Validity: 4 * 24 * time.Hour, Refresh: 30 * 24 * time.Hour}.Normalized()
	if p.Refresh != 2*24*time.Hour {
		t.Fatalf("refresh = %v, want half of the validity", p.Refresh)
	}
	d := dnssec.SigPolicy{}.Normalized()
	if d.Validity != 30*24*time.Hour || d.Refresh != 7*24*time.Hour {
		t.Fatalf("defaults = %+v", d)
	}
}

// ----------------------------------------------------- Secondary Zones

// pullSigned pulls the signed zone from p into a fresh Secondary Zone. The
// secondary has its own keys for the same zone name, which it must never use.
func pullSigned(t *testing.T, p *harness) (*harness, *secondary.Manager) {
	t.Helper()
	addr := startTCP(t, p.srv, nil)
	s := newHarness(t, withSigner())
	if err := s.signer.Ensure(zoneName); err != nil {
		t.Fatal(err)
	}
	mgr := secondary.New(filepath.Join(t.TempDir(), "secondary-zones.json"), s.auth, nil)
	s.srv.SetSecondary(mgr)
	if err := mgr.Upsert(secondary.Zone{Name: zoneName, Masters: []string{addr}}); err != nil {
		t.Fatal(err)
	}
	repull(t, mgr)
	return s, mgr
}

func repull(t *testing.T, mgr *secondary.Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mgr.Transfer(ctx, zoneName); err != nil {
		t.Fatal(err)
	}
}

// shape lists the owner and type of every record of a section, signatures as
// the type they cover, so two answers can be compared without their signature bytes.
func shape(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		k := dns.CanonicalName(rr.Header().Name) + " " + dns.TypeToString[rr.Header().Rrtype]
		if s, ok := rr.(*dns.RRSIG); ok {
			k += "(" + dns.TypeToString[s.TypeCovered] + ")"
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func wantSameShape(t *testing.T, what string, got, want []dns.RR) {
	t.Helper()
	if g, w := strings.Join(shape(got), "\n"), strings.Join(shape(want), "\n"); g != w {
		t.Errorf("%s differs from the primary's answer:\n got:\n%s\nwant:\n%s", what, g, w)
	}
}

// compareWithPrimary asks both servers the same question with DO set and checks
// that the secondary answers with the same records, signed by the primary's keys.
func compareWithPrimary(t *testing.T, p, s *harness, name string, qtype uint16) *dns.Msg {
	t.Helper()
	want := p.q(name, qtype, withDO())
	got := s.q(name, qtype, withDO())
	label := name + " " + dns.TypeToString[qtype]
	if got.Rcode != want.Rcode {
		t.Fatalf("%s: rcode %s, primary says %s", label, dns.RcodeToString[got.Rcode], dns.RcodeToString[want.Rcode])
	}
	wantSameShape(t, label+" answer", got.Answer, want.Answer)
	wantSameShape(t, label+" authority", got.Ns, want.Ns)
	keys := p.signer.DNSKEYs(zoneName)
	if len(got.Answer) > 0 {
		verifyEveryRRset(t, got, got.Answer, keys)
	}
	if len(got.Ns) > 0 {
		verifyEveryRRset(t, got, got.Ns, keys)
	}
	return got
}

func secondaryServesWhatItReceived(t *testing.T, nsec3 bool) {
	p := signedPrimary(t, nsec3)
	s, _ := pullSigned(t, p)

	queries := []struct {
		name  string
		qtype uint16
	}{
		{"www.example.com.", dns.TypeA},         // positive
		{"www.example.com.", dns.TypeTXT},       // positive, other type
		{"example.com.", dns.TypeSOA},           // the apex
		{"example.com.", dns.TypeDNSKEY},        // the keys, signed by the KSK
		{"example.com.", dns.TypeNS},            // apex NS
		{"missing.example.com.", dns.TypeA},     // NXDOMAIN
		{"x.www.example.com.", dns.TypeA},       // NXDOMAIN below a name
		{"zz.example.com.", dns.TypeA},          // NXDOMAIN after the last name
		{"www.example.com.", dns.TypeAAAA},      // NODATA
		{"z.example.com.", dns.TypeA},           // NODATA for an empty non-terminal
		{"foo.w.example.com.", dns.TypeA},       // answered through a wildcard
		{"a.b.w.example.com.", dns.TypeA},       // wildcard, deeper
		{"foo.w.example.com.", dns.TypeAAAA},    // wildcard NODATA
		{"x.c.example.com.", dns.TypeA},         // wildcard CNAME and its target
		{"example.com.", dns.TypeNSEC3PARAM},    // signed NSEC3PARAM (NODATA for an NSEC zone)
	}
	for _, q := range queries {
		got := compareWithPrimary(t, p, s, q.name, q.qtype)
		// Every signature in a Secondary Zone's answer comes from the primary's keys.
		for _, rr := range append(append([]dns.RR{}, got.Answer...), got.Ns...) {
			if sig, ok := rr.(*dns.RRSIG); ok {
				found := false
				for _, k := range p.signer.DNSKEYs(zoneName) {
					found = found || k.(*dns.DNSKEY).KeyTag() == sig.KeyTag
				}
				if !found {
					t.Errorf("%s %s: RRSIG by key tag %d is not one of the primary's keys", q.name, dns.TypeToString[q.qtype], sig.KeyTag)
				}
			}
		}
	}

	// Without DO nothing is added; the keys the secondary holds itself sign nothing.
	m := s.q("www.example.com.", dns.TypeA)
	wantA(t, m, "192.0.2.10")
	if len(rrsOfType(m.Answer, dns.TypeRRSIG)) != 0 {
		t.Fatalf("RRSIG without DO: %v", m.Answer)
	}
	m = s.q("missing.example.com.", dns.TypeA)
	if len(rrsOfType(m.Ns, dns.TypeRRSIG))+len(rrsOfType(m.Ns, dns.TypeNSEC))+len(rrsOfType(m.Ns, dns.TypeNSEC3)) != 0 {
		t.Fatalf("denial records without DO: %v", m.Ns)
	}
}

func TestSecondaryZoneServesAnNSECSignedZoneItReceivedWithoutSigningIt(t *testing.T) {
	secondaryServesWhatItReceived(t, false)
}

func TestSecondaryZoneServesAnNSEC3SignedZoneItReceivedWithoutSigningIt(t *testing.T) {
	secondaryServesWhatItReceived(t, true)
}

func TestSecondaryZoneStaysConsistentAcrossRecordAndSignatureRefreshes(t *testing.T) {
	p := signedPrimary(t, true, withConfig(func(c *config.Config) {
		c.Transfer.SignatureValidityDays = 30
		c.Transfer.SignatureRefreshDays = 7
	}))
	s, mgr := pullSigned(t, p)
	keys := p.signer.DNSKEYs(zoneName)
	serialOf := func(h *harness) uint32 { return h.auth.CurrentSOASerial(zoneName) }

	// 1. A record changes: the secondary pulls (an IXFR the primary answers in full).
	p.auth.AddRecord(zoneName, rec("new.example.com.", dns.TypeA, "192.0.2.55"))
	p.auth.DeleteRecord(zoneName, "b.example.com.", dns.TypeA)
	repull(t, mgr)
	if serialOf(s) != serialOf(p) {
		t.Fatalf("serial %d, primary %d", serialOf(s), serialOf(p))
	}
	compareWithPrimary(t, p, s, "new.example.com.", dns.TypeA)
	got := compareWithPrimary(t, p, s, "b.example.com.", dns.TypeA) // now NXDOMAIN, proven by the new chain
	if got.Rcode != dns.RcodeNameError {
		t.Fatalf("removed name answers %s", dns.RcodeToString[got.Rcode])
	}

	// 2. Only the signatures change (a new refresh interval): the serial moves, the
	// secondary pulls.
	serialBefore := serialOf(s)
	if bumped := p.srv.RefreshSignedZones(time.Now().Add(8 * 24 * time.Hour)); len(bumped) != 1 {
		t.Fatalf("refresh bumped %v", bumped)
	}
	repull(t, mgr)
	if serialOf(s) == serialBefore || serialOf(s) != serialOf(p) {
		t.Fatalf("serial %d (was %d), primary %d", serialOf(s), serialBefore, serialOf(p))
	}
	// What matters is that the pulled copy validates.
	verifyEveryRRset(t, &dns.Msg{}, s.q("new.example.com.", dns.TypeA, withDO()).Answer, keys)

	// 3. The ZSK is rolled: the secondary pulls the new DNSKEY RRset and signatures.
	if err := p.signer.RolloverZSK(zoneName); err != nil {
		t.Fatal(err)
	}
	if bumped := p.srv.RefreshSignedZones(time.Now()); len(bumped) != 1 {
		t.Fatalf("rollover bumped %v", bumped)
	}
	repull(t, mgr)
	compareWithPrimary(t, p, s, "example.com.", dns.TypeDNSKEY)
	compareWithPrimary(t, p, s, "new.example.com.", dns.TypeA)
	compareWithPrimary(t, p, s, "missing.example.com.", dns.TypeA)
}

func TestSecondaryZoneOfAnUnsignedZoneIsServedAsBefore(t *testing.T) {
	p := newHarness(t, withConfig(allowTransfer))
	p.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	addr := startTCP(t, p.srv, nil)
	s := newHarness(t)
	mgr := secondary.New(filepath.Join(t.TempDir(), "secondary-zones.json"), s.auth, nil)
	s.srv.SetSecondary(mgr)
	if err := mgr.Upsert(secondary.Zone{Name: zoneName, Masters: []string{addr}}); err != nil {
		t.Fatal(err)
	}
	repull(t, mgr)
	m := s.q("www.example.com.", dns.TypeA, withDO())
	wantA(t, m, "192.0.2.10")
	if len(rrsOfType(m.Answer, dns.TypeRRSIG)) != 0 {
		t.Fatalf("RRSIG from an unsigned Secondary Zone: %v", m.Answer)
	}
	m = s.q("missing.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeNameError)
	if len(m.Ns) != 1 {
		t.Fatalf("want only the SOA in authority, got %v", m.Ns)
	}
}
