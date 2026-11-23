package dnssec

import (
	"crypto"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// A key tag is a 16-bit checksum of the DNSKEY, so about one key in 65,536 has
// tag 0, and a ZSK shares its tag with the KSK about as often. miekg/dns refuses
// to sign with a key whose tag is 0 ("bad key"), and verifying with the wrong one
// of two keys that share a tag fails with "bad signature". These tests hand out
// such keys deterministically.

type minedKey struct {
	key  *dns.DNSKEY
	priv crypto.Signer
}

var (
	mineOnce   sync.Once
	zeroTagZSK minedKey
	baseKSK    minedKey
	collideZSK minedKey // same key tag as baseKSK
)

func mine(t *testing.T) {
	t.Helper()
	mineOnce.Do(func() {
		zone := "example.com."
		for {
			k, p, err := makeKey(zone, 256, dns.ECDSAP256SHA256)
			if err != nil {
				t.Fatal(err)
			}
			if k.KeyTag() == 0 {
				zeroTagZSK = minedKey{k, p}
				break
			}
		}
		k, p, err := makeKey(zone, 257, dns.ECDSAP256SHA256)
		if err != nil {
			t.Fatal(err)
		}
		baseKSK = minedKey{k, p}
		for {
			z, zp, err := makeKey(zone, 256, dns.ECDSAP256SHA256)
			if err != nil {
				t.Fatal(err)
			}
			if z.KeyTag() == baseKSK.key.KeyTag() {
				collideZSK = minedKey{z, zp}
				break
			}
		}
	})
}

// scriptKeys makes the generator return the given keys first, per flags, then
// real random ones.
func scriptKeys(t *testing.T, script map[uint16][]minedKey) {
	t.Helper()
	orig := makeKeyFn
	t.Cleanup(func() { makeKeyFn = orig })
	makeKeyFn = func(zone string, flags uint16, alg uint8) (*dns.DNSKEY, crypto.Signer, error) {
		if q := script[flags]; len(q) > 0 {
			script[flags] = q[1:]
			return q[0].key, q[0].priv, nil
		}
		return orig(zone, flags, alg)
	}
}

func signsA(t *testing.T, s *Signer, zone string) bool {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion("www."+zone, dns.TypeA)
	req.SetEdns0(1232, true)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 1}}}
	s.SignResponse(zone, req, resp)
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return true
		}
	}
	return false
}

func TestNewZoneNeverGetsAKeyTagOfZero(t *testing.T) {
	mine(t)
	scriptKeys(t, map[uint16][]minedKey{256: {zeroTagZSK}})
	s := NewSigner(t.TempDir())
	if err := s.Ensure("example.com."); err != nil {
		t.Fatal(err)
	}
	zk, _ := s.load("example.com.")
	if zk.ZSK.KeyTag() == 0 {
		t.Fatal("ZSK has key tag 0")
	}
	if !signsA(t, s, "example.com.") {
		t.Fatal("a signed zone returned an answer without RRSIG")
	}
}

func TestZSKRolloverNeverGivesAKeyTagOfZero(t *testing.T) {
	mine(t)
	s := NewSigner(t.TempDir())
	if err := s.Ensure("example.com."); err != nil {
		t.Fatal(err)
	}
	scriptKeys(t, map[uint16][]minedKey{256: {zeroTagZSK}})
	if err := s.RolloverZSK("example.com."); err != nil {
		t.Fatal(err)
	}
	if !signsA(t, s, "example.com.") {
		t.Fatal("no RRSIG after a ZSK rollover")
	}
}

func TestZSKDoesNotShareItsKeyTagWithTheKSK(t *testing.T) {
	mine(t)
	scriptKeys(t, map[uint16][]minedKey{257: {baseKSK}, 256: {collideZSK}})
	s := NewSigner(t.TempDir())
	if err := s.Ensure("example.com."); err != nil {
		t.Fatal(err)
	}
	zk, _ := s.load("example.com.")
	if zk.ZSK.KeyTag() == zk.KSK.KeyTag() {
		t.Fatalf("ZSK and KSK share key tag %d", zk.ZSK.KeyTag())
	}
}
