package server

// End-to-end tests for authenticated denial of existence in NSEC3-signed zones
// (RFC 5155 sections 7 and 8). The checks are written the way a validating
// resolver works: read the NSEC3 parameters from the records, hash names with
// them, and look for matching and covering records. The independent validator
// test is in test/dnssecdenial.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/dnssec"
)

const base32hex = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

// nsec3Zone builds an NSEC3-signed zone. An empty salt makes the signer draw a
// random one, which is what a zone gets in the field.
func nsec3Zone(t *testing.T, salt string, opts ...option) *harness {
	t.Helper()
	h := newHarness(t, opts...)
	h.signer = dnssec.NewSigner(t.TempDir())
	h.srv.signer = h.signer // the harness has no option for NSEC3 zones
	h.auth.UpsertZone(zoneName)
	h.auth.AddRecord(zoneName, authoritative.Record{Name: zoneName, Type: dns.TypeSOA, TTL: 300, Content: soaContent})
	h.auth.AddRecord(zoneName, rec(zoneName, dns.TypeNS, "ns1.example.com."))
	h.auth.AddRecord(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	h.auth.AddRecord(zoneName, rec("www.example.com.", dns.TypeTXT, "hello"))
	h.auth.AddRecord(zoneName, rec("a.z.example.com.", dns.TypeAAAA, "2001:db8::1")) // z.example.com. is an empty non-terminal
	if err := h.signer.EnsureWithOptions(zoneName, dnssec.SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: true, Salt: salt}); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) nsec3Salt() string {
	pol, ok := h.signer.Policy(zoneName)
	if !ok || pol.Salt == "" {
		h.t.Fatal("NSEC3 zone has no salt")
	}
	return pol.Salt
}

// zoneHashEndingIn finds a name under the zone, not in it, whose NSEC3 hash ends
// in c.
func zoneHashEndingIn(t *testing.T, salt string, c byte) string {
	t.Helper()
	for i := 0; i < 20000; i++ {
		n := fmt.Sprintf("n%d.example.com.", i)
		if h := dns.HashName(n, dns.SHA1, 1, salt); h != "" && h[len(h)-1] == c {
			return n
		}
	}
	t.Fatalf("no name with a hash ending in %c", c)
	return ""
}

func nsec3sOf(m *dns.Msg) []*dns.NSEC3 {
	var out []*dns.NSEC3
	for _, rr := range rrsOfType(m.Ns, dns.TypeNSEC3) {
		out = append(out, rr.(*dns.NSEC3))
	}
	return out
}

func matchingNSEC3(ns []*dns.NSEC3, name string) *dns.NSEC3 {
	for _, n := range ns {
		if n.Match(name) {
			return n
		}
	}
	return nil
}

func coveringNSEC3(ns []*dns.NSEC3, name string) *dns.NSEC3 {
	for _, n := range ns {
		if n.Cover(name) {
			return n
		}
	}
	return nil
}

// wantNSEC3Proof checks the reply as a validator would. existing is every name
// that exists in the zone, empty non-terminals included.
func wantNSEC3Proof(t *testing.T, h *harness, m *dns.Msg, qname string, qtype uint16, existing map[string]bool) {
	t.Helper()
	ns := nsec3sOf(m)
	if len(ns) == 0 {
		t.Fatalf("%s: no NSEC3 in %v", qname, m.Ns)
	}
	if len(rrsOfType(m.Ns, dns.TypeNSEC)) != 0 {
		t.Fatalf("%s: NSEC in an NSEC3 zone: %v", qname, m.Ns)
	}
	for _, n := range ns {
		if n.Hash != dns.SHA1 || n.Flags != 0 || n.Salt != h.nsec3Salt() {
			t.Errorf("%s: unexpected NSEC3 parameters %+v", qname, n)
		}
		label := strings.SplitN(n.Hdr.Name, ".", 2)[0]
		if strings.Trim(label, base32hex) != "" || strings.Trim(n.NextDomain, base32hex) != "" {
			t.Errorf("%s: owner %q or next %q is not base32hex", qname, label, n.NextDomain)
		}
	}
	verifyEveryRRset(t, m, m.Ns, h.signer.DNSKEYs(zoneName))
	wantSOAInAuthority(t, m, zoneName)

	if m.Rcode == dns.RcodeSuccess {
		n := matchingNSEC3(ns, qname)
		if n == nil {
			t.Fatalf("NODATA %s: no matching NSEC3 in %v", qname, m.Ns)
		}
		for _, typ := range n.TypeBitMap {
			if typ == qtype || typ == dns.TypeNSEC {
				t.Errorf("NODATA %s: bitmap %v lists %s", qname, n.TypeBitMap, dns.TypeToString[typ])
			}
		}
		return
	}

	// NXDOMAIN: find the closest encloser the way a resolver does.
	labels := dns.SplitDomainName(qname)
	for i := 1; i < len(labels); i++ {
		ce := dns.Fqdn(strings.Join(labels[i:], "."))
		if matchingNSEC3(ns, ce) == nil {
			continue
		}
		if !existing[ce] {
			t.Fatalf("%s: NSEC3 proves %s exists but it does not", qname, ce)
		}
		next := dns.Fqdn(strings.Join(labels[i-1:], "."))
		if coveringNSEC3(ns, next) == nil {
			t.Fatalf("%s: next closer name %s is not covered by %v", qname, next, m.Ns)
		}
		if w := "*." + ce; coveringNSEC3(ns, w) == nil {
			t.Fatalf("%s: wildcard %s is not covered by %v", qname, w, m.Ns)
		}
		// The closest encloser must be the deepest name that exists.
		for j := 1; j < i; j++ {
			if deeper := dns.Fqdn(strings.Join(labels[j:], ".")); existing[deeper] {
				t.Fatalf("%s: proof uses %s but %s exists", qname, ce, deeper)
			}
		}
		return
	}
	t.Fatalf("%s: no closest encloser proven in %v", qname, m.Ns)
}

var nsec3ZoneNames = map[string]bool{
	"example.com.": true, "www.example.com.": true, "a.z.example.com.": true, "z.example.com.": true,
}

func TestNSEC3SignedZoneNXDOMAINCarriesTheClosestEncloserProof(t *testing.T) {
	h := nsec3Zone(t, "")
	m := h.q("missing.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeNameError)
	wantNSEC3Proof(t, h, m, "missing.example.com.", dns.TypeA, nsec3ZoneNames)
}

func TestNSEC3SignedZoneNXDOMAINBelowAnExistingNameUsesThatNameAsClosestEncloser(t *testing.T) {
	h := nsec3Zone(t, "")
	m := h.q("deep.er.www.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeNameError)
	wantNSEC3Proof(t, h, m, "deep.er.www.example.com.", dns.TypeA, nsec3ZoneNames)
	if matchingNSEC3(nsec3sOf(m), "www.example.com.") == nil {
		t.Fatalf("closest encloser www.example.com. has no matching NSEC3: %v", m.Ns)
	}
}

func TestNSEC3SignedZoneNODATACarriesTheMatchingNSEC3(t *testing.T) {
	h := nsec3Zone(t, "")
	m := h.q("www.example.com.", dns.TypeAAAA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 0 {
		t.Fatalf("NODATA carries answers: %v", m.Answer)
	}
	wantNSEC3Proof(t, h, m, "www.example.com.", dns.TypeAAAA, nsec3ZoneNames)
	n := matchingNSEC3(nsec3sOf(m), "www.example.com.")
	if got, want := fmt.Sprint(n.TypeBitMap), fmt.Sprint([]uint16{dns.TypeA, dns.TypeTXT, dns.TypeRRSIG}); got != want {
		t.Errorf("bitmap of www = %s want %s", got, want)
	}
}

func TestNSEC3SignedZoneNODATAAtTheApexListsTheKeyTypes(t *testing.T) {
	h := nsec3Zone(t, "")
	m := h.q("example.com.", dns.TypeTXT, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	wantNSEC3Proof(t, h, m, "example.com.", dns.TypeTXT, nsec3ZoneNames)
	n := matchingNSEC3(nsec3sOf(m), "example.com.")
	if got, want := fmt.Sprint(n.TypeBitMap), fmt.Sprint([]uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM}); got != want {
		t.Errorf("bitmap of the apex = %s want %s", got, want)
	}
}

func TestNSEC3SignedZoneNODATAForAnEmptyNonTerminalHasAnEmptyBitmap(t *testing.T) {
	h := nsec3Zone(t, "")
	m := h.q("z.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	wantNSEC3Proof(t, h, m, "z.example.com.", dns.TypeA, nsec3ZoneNames)
	if n := matchingNSEC3(nsec3sOf(m), "z.example.com."); len(n.TypeBitMap) != 0 {
		t.Errorf("empty non-terminal bitmap = %v want none", n.TypeBitMap)
	}
}

// Every missing name is answered with a verifiable proof, whatever character its
// hash ends in and whatever the salt: 20 random salts x 32 final characters.
func TestNSEC3SignedZoneNXDOMAINIsSignedForAnySaltAndAnyHashEnding(t *testing.T) {
	for s := 0; s < 20; s++ {
		h := nsec3Zone(t, "")
		salt := h.nsec3Salt()
		for _, c := range []byte(base32hex) {
			name := zoneHashEndingIn(t, salt, c)
			m := h.q(name, dns.TypeA, withDO())
			wantRcode(t, m, dns.RcodeNameError)
			wantNSEC3Proof(t, h, m, name, dns.TypeA, nsec3ZoneNames)
		}
	}
}

func TestNSEC3SignedZoneKeepsTheSaltInTheOnDiskPolicy(t *testing.T) {
	h := nsec3Zone(t, "")
	salt := h.nsec3Salt()
	m1 := h.q("missing.example.com.", dns.TypeA, withDO())
	m2 := h.q("other.example.com.", dns.TypeA, withDO())
	for _, m := range []*dns.Msg{m1, m2} {
		for _, n := range nsec3sOf(m) {
			if n.Salt != salt {
				t.Fatalf("NSEC3 salt %s differs from the zone's %s", n.Salt, salt)
			}
		}
	}
}

func TestNSEC3DenialHasNoRecordsWithoutDNSSECOK(t *testing.T) {
	h := nsec3Zone(t, "")
	m := h.q("missing.example.com.", dns.TypeA)
	if len(m.Ns) != 1 || m.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("authority without DO should be the SOA only: %v", m.Ns)
	}
}

// The case that used to produce an unpackable NSEC3: a missing name whose hash
// ends in '9' (the old code computed the next hash by adding one to that character).
func TestNSEC3SignedZoneNXDOMAINIsSignedWhenTheNameHashEndsInNine(t *testing.T) {
	h := nsec3Zone(t, "")
	name := zoneHashEndingIn(t, h.nsec3Salt(), '9')
	m := h.q(name, dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeNameError)
	wantNSEC3Proof(t, h, m, name, dns.TypeA, nsec3ZoneNames)
}

func TestNSEC3SignedZoneNODATAForANameThatOnlyAWildcardCoversProvesTheWildcard(t *testing.T) {
	h := nsec3Zone(t, "")
	h.auth.AddRecord(zoneName, rec("*.w.example.com.", dns.TypeA, "192.0.2.77"))
	m := h.q("foo.w.example.com.", dns.TypeAAAA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	ns := nsec3sOf(m)
	if matchingNSEC3(ns, "w.example.com.") == nil || matchingNSEC3(ns, "*.w.example.com.") == nil || coveringNSEC3(ns, "foo.w.example.com.") == nil {
		t.Fatalf("want match for the closest encloser and the wildcard, and a cover for the next closer name: %v", m.Ns)
	}
	if n := matchingNSEC3(ns, "*.w.example.com."); fmt.Sprint(n.TypeBitMap) != fmt.Sprint([]uint16{dns.TypeA, dns.TypeRRSIG}) {
		t.Errorf("wildcard bitmap = %v", n.TypeBitMap)
	}
	verifyEveryRRset(t, m, m.Ns, h.signer.DNSKEYs(zoneName))
}
