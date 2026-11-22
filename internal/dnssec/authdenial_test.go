package dnssec

import (
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// RFC 4034 section 6.1 lists names in canonical order.
func TestCanonicalCompareFollowsRFC4034Section61(t *testing.T) {
	ordered := []string{
		"example.",
		"a.example.",
		"yljkjljk.a.example.",
		"Z.a.example.",
		"zABC.a.EXAMPLE.",
		"z.example.",
		"\\001.z.example.",
		"*.z.example.",
		"\\200.z.example.",
	}
	for i := range ordered {
		for j := range ordered {
			got := canonicalCompare(ordered[i], ordered[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got != want {
				t.Errorf("canonicalCompare(%q, %q)=%d want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
}

func TestCanonicalCompareIgnoresCase(t *testing.T) {
	if canonicalCompare("WWW.Example.COM.", "www.example.com.") != 0 {
		t.Fatal("names differing only in case must compare equal")
	}
}

func newTestSigner(t *testing.T, zone string) (*Signer, *zoneKeys) {
	t.Helper()
	s := NewSigner(t.TempDir())
	if err := s.EnsureWithOptions(zone, SignOptions{Algorithm: dns.ECDSAP256SHA256}); err != nil {
		t.Fatal(err)
	}
	zk, err := s.load(zone)
	if err != nil {
		t.Fatal(err)
	}
	return s, zk
}

func denialReq() *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("q.example.com.", dns.TypeA)
	req.SetEdns0(1232, true)
	return req
}

func randomLabel(r *rand.Rand) string {
	const alphabet = "abcxyzABCXYZ019-"
	n := 1 + r.Intn(3)
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func randomName(r *rand.Rand, zone string) string {
	depth := 1 + r.Intn(3)
	name := zone
	for i := 0; i < depth; i++ {
		name = randomLabel(r) + "." + name
	}
	if r.Intn(8) == 0 {
		name = "*." + name
	}
	return name
}

// Whatever the zone and the name asked, the proof must pack, every NSEC must
// verify, and the NSEC records must prove what RFC 4035 section 3.1.3 says.
func TestNSECProofIsValidForRandomZones(t *testing.T) {
	const zone = "example.com."
	s, zk := newTestSigner(t, zone)
	seed := time.Now().UnixNano()
	r := rand.New(rand.NewSource(seed))
	t.Logf("seed %d", seed)

	names := map[string][]uint16{zone: {dns.TypeSOA, dns.TypeNS}}
	for i, n := 0, 1+r.Intn(12); i < n; i++ {
		types := []uint16{dns.TypeA}
		if r.Intn(2) == 0 {
			types = append(types, dns.TypeTXT, dns.TypeAAAA)
		}
		names[randomName(r, zone)] = types
	}
	exists := map[string]bool{}
	for n := range names {
		for p := dns.CanonicalName(n); ; p = parentOf(p) {
			exists[p] = true
			if p == zone {
				break
			}
		}
	}

	for i := 0; i < 40; i++ {
		q := randomName(r, zone)
		resp := new(dns.Msg)
		resp.SetReply(denialReq())
		resp.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1." + zone, Mbox: "h." + zone, Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minttl: 60}}
		cq := dns.CanonicalName(q)
		_, qHasRecords := names[cq]
		for n := range names {
			if dns.CanonicalName(n) == cq {
				qHasRecords = true
			}
		}
		nx := !exists[cq]
		if nx {
			resp.Rcode = dns.RcodeNameError
		}
		if err := s.signNSECDenial(zone, q, zk, names, time.Now().UTC(), resp); err != nil {
			t.Fatalf("seed %d %s: %v", seed, q, err)
		}
		if _, err := resp.Pack(); err != nil {
			t.Fatalf("seed %d %s does not pack: %v\n%v", seed, q, err, resp.Ns)
		}
		var nsecs []*dns.NSEC
		for _, rr := range resp.Ns {
			if n, ok := rr.(*dns.NSEC); ok {
				nsecs = append(nsecs, n)
				if n.Hdr.Ttl != 60 {
					t.Fatalf("NSEC TTL=%d want SOA minimum 60", n.Hdr.Ttl)
				}
				for j := 1; j < len(n.TypeBitMap); j++ {
					if n.TypeBitMap[j-1] >= n.TypeBitMap[j] {
						t.Fatalf("bitmap not strictly ascending: %v", n.TypeBitMap)
					}
				}
			}
		}
		verifySet(t, resp.Ns, zk)
		covers := func(name string) bool {
			for _, n := range nsecs {
				if nsecCoversCanonical(n.Hdr.Name, n.NextDomain, name) {
					return true
				}
			}
			return false
		}
		matches := func(name string) bool {
			for _, n := range nsecs {
				if canonicalCompare(n.Hdr.Name, name) == 0 {
					return true
				}
			}
			return false
		}
		switch {
		case nx:
			if !covers(q) {
				t.Fatalf("seed %d: NXDOMAIN %s not covered by %v", seed, q, resp.Ns)
			}
			ce := parentOf(cq)
			for !exists[ce] {
				ce = parentOf(ce)
			}
			if w := "*." + ce; !covers(w) && !matches(w) {
				t.Fatalf("seed %d: wildcard %s at closest encloser %s not covered by %v", seed, w, ce, resp.Ns)
			}
		case qHasRecords:
			if !matches(q) {
				t.Fatalf("seed %d: NODATA %s has no matching NSEC: %v", seed, q, resp.Ns)
			}
		default: // empty non-terminal
			if !covers(q) {
				t.Fatalf("seed %d: empty non-terminal %s not covered: %v", seed, q, resp.Ns)
			}
		}
	}
}

// nsecCoversCanonical is a reference check, written against the sorted order
// rather than the chain code: owner < name < next, with the last NSEC wrapping.
func nsecCoversCanonical(owner, next, name string) bool {
	if canonicalCompare(owner, next) < 0 {
		return canonicalCompare(owner, name) < 0 && canonicalCompare(name, next) < 0
	}
	return canonicalCompare(owner, name) < 0 || canonicalCompare(name, next) < 0
}

func verifySet(t *testing.T, rrs []dns.RR, zk *zoneKeys) {
	t.Helper()
	groups := map[string][]dns.RR{}
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		k := dns.CanonicalName(rr.Header().Name) + "/" + dns.TypeToString[rr.Header().Rrtype]
		groups[k] = append(groups[k], rr)
	}
	for k, set := range groups {
		ok := false
		for _, rr := range rrs {
			sig, isSig := rr.(*dns.RRSIG)
			if !isSig || dns.CanonicalName(sig.Hdr.Name)+"/"+dns.TypeToString[sig.TypeCovered] != k {
				continue
			}
			if err := sig.Verify(zk.ZSK, set); err != nil {
				t.Fatalf("RRSIG over %s: %v", k, err)
			}
			ok = true
		}
		if !ok {
			t.Fatalf("no RRSIG over %s", k)
		}
	}
}

func TestNSECChainIsClosedAndSortedForAnyZone(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const zone = "example.com."
	names := map[string][]uint16{}
	for i := 0; i < 30; i++ {
		names[randomName(r, zone)] = []uint16{dns.TypeA}
	}
	z := newDenialZone(zone, names)
	if z.chain[0] != zone {
		t.Fatalf("chain must start at the apex, got %s", z.chain[0])
	}
	if !sort.SliceIsSorted(z.chain, func(i, j int) bool { return canonicalCompare(z.chain[i], z.chain[j]) < 0 }) {
		t.Fatalf("chain not in canonical order: %v", z.chain)
	}
	for i := range z.chain {
		n := z.nsecAt(i, 60)
		if want := z.chain[(i+1)%len(z.chain)]; n.NextDomain != want {
			t.Fatalf("NSEC %s next=%s want %s", n.Hdr.Name, n.NextDomain, want)
		}
		if strings.ToLower(n.Hdr.Name) != n.Hdr.Name {
			t.Fatalf("chain owner is not canonical: %s", n.Hdr.Name)
		}
	}
}

func TestNSECOnlyAnswersWhenDNSSECOKIsSet(t *testing.T) {
	const zone = "example.com."
	s, _ := newTestSigner(t, zone)
	req := new(dns.Msg)
	req.SetQuestion("q.example.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)
	if err := s.SignDenialForNames(zone, "q.example.com.", nil, req, resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Ns) != 0 {
		t.Fatalf("denial records without DO: %v", resp.Ns)
	}
}
