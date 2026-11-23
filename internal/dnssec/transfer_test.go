package dnssec

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func transferSigner(t *testing.T, nsec3 bool) *Signer {
	t.Helper()
	s := NewSigner(t.TempDir())
	if err := s.EnsureWithOptions("example.com.", SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: nsec3}); err != nil {
		t.Fatal(err)
	}
	return s
}

var transferNames = map[string][]uint16{
	"example.com.":     {dns.TypeSOA, dns.TypeNS},
	"www.example.com.": {dns.TypeA, dns.TypeTXT},
	"b.example.com.":   {dns.TypeA},
	"a.z.example.com.": {dns.TypeAAAA}, // z.example.com. is an empty non-terminal
	"*.w.example.com.": {dns.TypeA},
}

func TestSigPolicyWindowsAreStableWithinAnIntervalAndMoveWithTheNext(t *testing.T) {
	p := SigPolicy{Validity: 30 * 24 * time.Hour, Refresh: 7 * 24 * time.Hour}
	t0 := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	in0, ex0 := p.Window(t0)
	in1, ex1 := p.Window(t0.Add(time.Hour))
	if in0 != in1 || ex0 != ex1 {
		t.Fatal("window changed inside one refresh interval")
	}
	in2, ex2 := p.Window(t0.Add(8 * 24 * time.Hour))
	if in2 <= in0 || ex2 <= ex0 {
		t.Fatal("window did not move with the next interval")
	}
	for _, at := range []time.Time{t0, t0.Add(6*24*time.Hour + 23*time.Hour), t0.Add(8 * 24 * time.Hour)} {
		in, ex := p.Window(at)
		if int64(in) > at.Unix() {
			t.Errorf("inception %d is after %v", in, at)
		}
		if left := time.Unix(int64(ex), 0).Sub(at); left < 23*24*time.Hour {
			t.Errorf("only %v of validity left at %v", left, at)
		}
	}
}

func TestForTransferSignsWithTheTransferWindowAndTheRightKeys(t *testing.T) {
	s := transferSigner(t, false)
	now := time.Now()
	zs, err := s.ForTransfer("example.com.", SigPolicy{}, now)
	if err != nil {
		t.Fatal(err)
	}
	in, ex := SigPolicy{}.Window(now)

	a := &dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 1}}
	sig, err := zs.Sign([]dns.RR{a})
	if err != nil {
		t.Fatal(err)
	}
	if sig.Inception != in || sig.Expiration != ex {
		t.Fatalf("window %d-%d, want %d-%d", sig.Inception, sig.Expiration, in, ex)
	}
	keys := zs.Keys()
	zsk, ksk := keys[0].(*dns.DNSKEY), keys[1].(*dns.DNSKEY)
	if sig.KeyTag != zsk.KeyTag() {
		t.Error("ordinary RRset must be signed by the ZSK")
	}
	if err := sig.Verify(zsk, []dns.RR{a}); err != nil {
		t.Fatal(err)
	}
	ksig, err := zs.Sign(keys)
	if err != nil {
		t.Fatal(err)
	}
	if ksig.KeyTag != ksk.KeyTag() {
		t.Error("DNSKEY RRset must be signed by the KSK")
	}
	if err := ksig.Verify(ksk, keys); err != nil {
		t.Fatal(err)
	}
	if zs.NSEC3PARAM(300) != nil {
		t.Error("NSEC zone has no NSEC3PARAM")
	}
}

func TestChainIsTheClosedNSECChainOfEveryOwner(t *testing.T) {
	s := transferSigner(t, false)
	zs, _ := s.ForTransfer("example.com.", SigPolicy{}, time.Now())
	chain := zs.Chain(transferNames, 300)
	if len(chain) != len(transferNames) {
		t.Fatalf("%d NSEC for %d names", len(chain), len(transferNames))
	}
	for i, rr := range chain {
		n := rr.(*dns.NSEC)
		if next := chain[(i+1)%len(chain)].Header().Name; n.NextDomain != next {
			t.Errorf("%s points to %s, want %s", n.Hdr.Name, n.NextDomain, next)
		}
	}
	if chain[0].Header().Name != "example.com." {
		t.Fatalf("chain starts at %s", chain[0].Header().Name)
	}
	apex := chain[0].(*dns.NSEC).TypeBitMap
	want := []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if fmt.Sprint(apex) != fmt.Sprint(want) {
		t.Errorf("apex bitmap %v, want %v", apex, want)
	}
}

func TestChainOfAnNSEC3ZoneIncludesTheEmptyNonTerminalsAndNSEC3PARAM(t *testing.T) {
	s := transferSigner(t, true)
	zs, _ := s.ForTransfer("example.com.", SigPolicy{}, time.Now())
	chain := zs.Chain(transferNames, 300)
	if len(chain) != len(transferNames)+2 { // z.example.com. and w.example.com.
		t.Fatalf("%d NSEC3 records for %d names and 2 empty non-terminals", len(chain), len(transferNames))
	}
	np := zs.NSEC3PARAM(300)
	if np == nil || np.Hash != dns.SHA1 || np.Iterations != 1 || np.Flags != 0 {
		t.Fatalf("NSEC3PARAM = %v", np)
	}
	apexHash := strings.ToUpper(dns.HashName("example.com.", dns.SHA1, 1, np.Salt))
	for _, rr := range chain {
		n := rr.(*dns.NSEC3)
		if n.Salt != np.Salt {
			t.Errorf("NSEC3 salt %q differs from NSEC3PARAM %q", n.Salt, np.Salt)
		}
		if strings.HasPrefix(strings.ToUpper(n.Hdr.Name), apexHash) {
			found := false
			for _, ty := range n.TypeBitMap {
				found = found || ty == dns.TypeNSEC3PARAM
			}
			if !found {
				t.Error("apex NSEC3 bitmap lacks NSEC3PARAM")
			}
		}
	}
}

var proofQueries = []string{
	"missing.example.com.", "x.www.example.com.", "zz.example.com.", "aa.example.com.",
	"www.example.com.", "z.example.com.", "a.z.example.com.", "foo.w.example.com.", "a.b.w.example.com.",
	"w.example.com.", "example.com.", "deep.below.missing.example.com.",
}

func ownerSet(rrs interface{}) string {
	var out []string
	switch v := rrs.(type) {
	case []dns.RR:
		for _, rr := range v {
			out = append(out, dns.CanonicalName(rr.Header().Name))
		}
	case []*dns.NSEC:
		for _, rr := range v {
			out = append(out, dns.CanonicalName(rr.Hdr.Name))
		}
	case []*dns.NSEC3:
		for _, rr := range v {
			out = append(out, dns.CanonicalName(rr.Hdr.Name))
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestPresignedProofPicksTheRecordsTheSignerWouldHaveSent(t *testing.T) {
	var dataNames []string
	for n := range transferNames {
		dataNames = append(dataNames, n)
	}
	for _, nsec3 := range []bool{false, true} {
		s := transferSigner(t, nsec3)
		zs, _ := s.ForTransfer("example.com.", SigPolicy{}, time.Now())
		chain := zs.Chain(transferNames, 300)
		dz := newDenialZone("example.com.", transferNames)
		salt := zs.zk.Policy.nsec3Salt()
		for _, q := range proofQueries {
			for _, kind := range []ProofKind{ProofNXDOMAIN, ProofNODATA} {
				got := ownerSet(PresignedProof("example.com.", q, kind, dataNames, chain))
				var want string
				if nsec3 {
					want = ownerSet(dz.nsec3Proof(q, salt, kind == ProofNXDOMAIN, 300))
				} else {
					want = ownerSet(dz.nsecProof(q, kind == ProofNXDOMAIN, 300))
				}
				if got != want {
					t.Errorf("nsec3=%v %s kind=%d: got %s want %s", nsec3, q, kind, got, want)
				}
			}
		}
	}
}

func TestPresignedProofForAWildcardExpansionIsTheCoverOfTheNameOrTheClosestEncloserProof(t *testing.T) {
	var dataNames []string
	for n := range transferNames {
		dataNames = append(dataNames, n)
	}
	s := transferSigner(t, false)
	zs, _ := s.ForTransfer("example.com.", SigPolicy{}, time.Now())
	chain := zs.Chain(transferNames, 300)
	got := PresignedProof("example.com.", "foo.w.example.com.", ProofWildcardExpansion, dataNames, chain)
	dz := newDenialZone("example.com.", transferNames)
	want := dz.nsecAt(dz.coverIndex("foo.w.example.com."), 300)
	if len(got) != 1 || dns.CanonicalName(got[0].Header().Name) != want.Hdr.Name {
		t.Fatalf("NSEC cover = %v, want %s", got, want.Hdr.Name)
	}

	s3 := transferSigner(t, true)
	zs3, _ := s3.ForTransfer("example.com.", SigPolicy{}, time.Now())
	got3 := PresignedProof("example.com.", "a.b.w.example.com.", ProofWildcardExpansion, dataNames, zs3.Chain(transferNames, 300))
	salt := zs3.zk.Policy.nsec3Salt()
	c := dz.nsec3Chain(salt)
	ce := dz.closestEncloser("a.b.w.example.com.")
	// The two lookups can land on the same record, which is then sent once.
	uniq := map[int]bool{
		c.matchOrCover(nsec3Hash(ce, salt)):                                   true,
		c.matchOrCover(nsec3Hash(nextCloser("a.b.w.example.com.", ce), salt)): true,
	}
	var wantRecs []*dns.NSEC3
	for i := range uniq {
		wantRecs = append(wantRecs, c.record(i, 300))
	}
	want3 := ownerSet(wantRecs)
	// ce is w.example.com., an empty non-terminal with its own NSEC3 record.
	if ownerSet(got3) != want3 {
		t.Fatalf("NSEC3 expansion proof = %s, want %s", ownerSet(got3), want3)
	}
}

func TestPresignedProofOfAZoneWithoutAChainIsEmpty(t *testing.T) {
	if got := PresignedProof("example.com.", "x.example.com.", ProofNXDOMAIN, []string{"example.com."}, nil); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestTransferRefreshIsDueOncePerIntervalPerKeySetAndPolicy(t *testing.T) {
	s := transferSigner(t, false)
	p := SigPolicy{Validity: 30 * 24 * time.Hour, Refresh: 7 * 24 * time.Hour}
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	mark := func(at time.Time) bool {
		fp, due := s.TransferRefreshDue("example.com.", p, at)
		if due {
			if err := s.MarkTransferRefreshed("example.com.", fp); err != nil {
				t.Fatal(err)
			}
		}
		return due
	}
	if !mark(now) {
		t.Fatal("a zone never marked is due")
	}
	if mark(now.Add(time.Hour)) {
		t.Fatal("due twice in one interval")
	}
	if !mark(now.Add(8 * 24 * time.Hour)) {
		t.Fatal("not due in the next interval")
	}
	if err := s.RolloverZSK("example.com."); err != nil {
		t.Fatal(err)
	}
	if !mark(now.Add(8 * 24 * time.Hour)) {
		t.Fatal("not due after a ZSK rollover")
	}
	if err := s.EnsureWithOptions("example.com.", SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: true}); err != nil {
		t.Fatal(err)
	}
	if !mark(now.Add(8 * 24 * time.Hour)) {
		t.Fatal("not due after switching to NSEC3")
	}
	if mark(now.Add(8 * 24 * time.Hour)) {
		t.Fatal("due again with nothing changed")
	}
	// The state is kept next to the keys: a new Signer over the directory agrees.
	s2 := NewSigner(s.dir)
	if _, due := s2.TransferRefreshDue("example.com.", p, now.Add(8*24*time.Hour)); due {
		t.Fatal("a restarted signer wants a refresh again")
	}
	if _, due := s.TransferRefreshDue("nokeys.test.", p, now); due {
		t.Fatal("a zone without keys is never due")
	}
}
