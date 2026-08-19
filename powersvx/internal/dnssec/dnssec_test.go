package dnssec

import (
	"crypto"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func genKey(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257, // KSK
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("private key is not a crypto.Signer")
	}
	return key, signer
}

func signA(t *testing.T, zone string, key *dns.DNSKEY, signer crypto.Signer) ([]dns.RR, *dns.RRSIG) {
	t.Helper()
	a, _ := dns.NewRR(zone + " 3600 IN A 192.0.2.10")
	rrset := []dns.RR{a}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(zone)),
		OrigTtl:     3600,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  zone,
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return rrset, sig
}

func TestVerifyRRSetOffline(t *testing.T) {
	zone := "example.test."
	key, signer := genKey(t, zone)
	rrset, sig := signA(t, zone, key, signer)

	if !verifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}) {
		t.Fatal("expected valid signature to verify")
	}

	bad, _ := dns.NewRR(zone + " 3600 IN A 203.0.113.99")
	if verifyRRSet([]dns.RR{bad}, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}) {
		t.Fatal("tampered rrset must not verify")
	}

	other, _ := genKey(t, zone)
	if verifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{other}) {
		t.Fatal("wrong key must not verify")
	}
}

func TestExpiredSignatureRejected(t *testing.T) {
	zone := "example.test."
	key, signer := genKey(t, zone)
	a, _ := dns.NewRR(zone + " 3600 IN A 192.0.2.10")
	rrset := []dns.RR{a}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(zone)),
		OrigTtl:     3600,
		Expiration:  uint32(time.Now().Add(-2 * time.Hour).Unix()), // already expired
		Inception:   uint32(time.Now().Add(-24 * time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  zone,
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if verifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}) {
		t.Fatal("expired signature must be rejected")
	}
}

func TestDSMatch(t *testing.T) {
	zone := "example.test."
	key, _ := genKey(t, zone)
	ds := key.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("ToDS returned nil")
	}
	if ds.KeyTag != key.KeyTag() {
		t.Errorf("keytag mismatch: ds=%d key=%d", ds.KeyTag, key.KeyTag())
	}
	ds2 := key.ToDS(dns.SHA256)
	if ds.KeyTag != ds2.KeyTag || ds.Digest != ds2.Digest {
		t.Error("DS not stable")
	}
}

func TestRootAnchorPresent(t *testing.T) {
	a := RootAnchors()
	if len(a) != 1 || a[0].KeyTag != 20326 {
		t.Fatalf("unexpected root anchor: %+v", a)
	}
}

func TestParentZone(t *testing.T) {
	cases := map[string]string{
		"a.b.example.com.": "b.example.com.",
		"example.com.":     "com.",
		"com.":             ".",
		".":                ".",
	}
	for in, want := range cases {
		if got := parentZone(in); got != want {
			t.Errorf("parentZone(%q)=%q want %q", in, got, want)
		}
	}
}
