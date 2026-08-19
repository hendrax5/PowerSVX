// Package dnssec is an optional, heavier validation path. It builds a chain of
// trust from the embedded root trust anchor down to the answer's signer zone:
//
//	answer RRset  <- verified by ZSK/KSK of signer zone
//	signer DNSKEY <- self-signed by KSK; KSK hash matches parent DS
//	parent DS     <- signed by parent DNSKEY ... up to the root anchor
//
// Scope: positive-answer validation. Unsigned/insecure zones (no DS) are
// reported Insecure (served without AD), a present-but-failing signature or a
// broken chain is Bogus (caller returns SERVFAIL). Denial-of-existence
// (NSEC/NSEC3) is not yet validated and is treated as Insecure.
package dnssec

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Status int

const (
	Insecure Status = iota
	Secure
	Bogus
)

func (s Status) String() string {
	switch s {
	case Secure:
		return "secure"
	case Bogus:
		return "bogus"
	default:
		return "insecure"
	}
}

// errInsecure signals that a zone in the chain has no DS (unsigned delegation).
var errInsecure = errors.New("dnssec: insecure zone")

// QueryFunc resolves name/qtype and returns the (DO-enabled) response.
type QueryFunc func(name string, qtype uint16) (*dns.Msg, error)

type Validator struct {
	anchors []*dns.DS
	query   QueryFunc

	mu   sync.Mutex
	keys map[string][]*dns.DNSKEY // validated DNSKEYs per zone
}

func NewValidator(query QueryFunc) *Validator {
	return &Validator{anchors: RootAnchors(), query: query, keys: make(map[string][]*dns.DNSKEY)}
}

// RootAnchors returns the IANA root KSK trust anchor (KSK-2017, tag 20326).
func RootAnchors() []*dns.DS {
	return []*dns.DS{{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     20326,
		Algorithm:  8, // RSASHA256
		DigestType: 2, // SHA-256
		Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	}}
}

// Validate checks the positive answer for (qname,qtype).
func (v *Validator) Validate(answer *dns.Msg, qname string, qtype uint16) (Status, error) {
	rrset, sigs := splitRRSIG(answer.Answer, qtype)
	if len(rrset) == 0 {
		return Insecure, nil // e.g. CNAME-only / NODATA: not handled here
	}
	if len(sigs) == 0 {
		return Insecure, nil // unsigned
	}
	signer := strings.ToLower(sigs[0].SignerName)
	keys, err := v.fetchKeys(signer, 0)
	if err != nil {
		if errors.Is(err, errInsecure) {
			return Insecure, nil
		}
		return Bogus, err
	}
	if verifyRRSet(rrset, sigs, keys) {
		return Secure, nil
	}
	return Bogus, fmt.Errorf("dnssec: answer signature invalid for %s/%d", qname, qtype)
}

// fetchKeys returns the validated DNSKEY set for a zone.
func (v *Validator) fetchKeys(zone string, depth int) ([]*dns.DNSKEY, error) {
	zone = dns.Fqdn(strings.ToLower(zone))
	v.mu.Lock()
	if k, ok := v.keys[zone]; ok {
		v.mu.Unlock()
		return k, nil
	}
	v.mu.Unlock()
	if depth > 20 {
		return nil, errors.New("dnssec: chain too deep")
	}

	dsSet, err := v.fetchDS(zone, depth)
	if err != nil {
		return nil, err
	}

	msg, err := v.query(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	var keys []*dns.DNSKEY
	var sigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		switch t := rr.(type) {
		case *dns.DNSKEY:
			keys = append(keys, t)
		case *dns.RRSIG:
			if t.TypeCovered == dns.TypeDNSKEY {
				sigs = append(sigs, t)
			}
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("dnssec: no DNSKEY for %s", zone)
	}

	// A KSK in the set must hash to one of the parent DS records.
	var ksk *dns.DNSKEY
	for _, k := range keys {
		for _, ds := range dsSet {
			if kd := k.ToDS(ds.DigestType); kd != nil &&
				kd.KeyTag == ds.KeyTag && strings.EqualFold(kd.Digest, ds.Digest) {
				ksk = k
				break
			}
		}
		if ksk != nil {
			break
		}
	}
	if ksk == nil {
		return nil, fmt.Errorf("dnssec: no KSK matches DS for %s", zone)
	}

	// The DNSKEY RRset must be self-signed by that KSK.
	dnskeyRRset := dnskeyRRs(keys)
	if !verifyRRSetWithKey(dnskeyRRset, sigs, ksk) {
		return nil, fmt.Errorf("dnssec: DNSKEY set not signed by trusted KSK for %s", zone)
	}

	v.mu.Lock()
	v.keys[zone] = keys
	v.mu.Unlock()
	return keys, nil
}

// fetchDS returns the validated DS set for a zone (its parent signs it).
func (v *Validator) fetchDS(zone string, depth int) ([]*dns.DS, error) {
	zone = dns.Fqdn(strings.ToLower(zone))
	if zone == "." {
		return v.anchors, nil
	}
	msg, err := v.query(zone, dns.TypeDS)
	if err != nil {
		return nil, err
	}
	var dsSet []*dns.DS
	var sigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		switch t := rr.(type) {
		case *dns.DS:
			dsSet = append(dsSet, t)
		case *dns.RRSIG:
			if t.TypeCovered == dns.TypeDS {
				sigs = append(sigs, t)
			}
		}
	}
	if len(dsSet) == 0 {
		return nil, errInsecure // unsigned delegation
	}
	signer := parentZone(zone)
	if len(sigs) > 0 {
		signer = strings.ToLower(sigs[0].SignerName)
	}
	parentKeys, err := v.fetchKeys(signer, depth+1)
	if err != nil {
		return nil, err
	}
	if !verifyRRSet(dsRRs(dsSet), sigs, parentKeys) {
		return nil, fmt.Errorf("dnssec: DS set signature invalid for %s", zone)
	}
	return dsSet, nil
}

// --- verification helpers ---

func verifyRRSet(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY) bool {
	now := time.Now()
	for _, sig := range sigs {
		if !sig.ValidityPeriod(now) {
			continue
		}
		for _, k := range keys {
			if k.KeyTag() == sig.KeyTag && k.Algorithm == sig.Algorithm {
				if sig.Verify(k, rrset) == nil {
					return true
				}
			}
		}
	}
	return false
}

func verifyRRSetWithKey(rrset []dns.RR, sigs []*dns.RRSIG, key *dns.DNSKEY) bool {
	now := time.Now()
	for _, sig := range sigs {
		if !sig.ValidityPeriod(now) {
			continue
		}
		if key.KeyTag() == sig.KeyTag && key.Algorithm == sig.Algorithm {
			if sig.Verify(key, rrset) == nil {
				return true
			}
		}
	}
	return false
}

func splitRRSIG(rrs []dns.RR, qtype uint16) ([]dns.RR, []*dns.RRSIG) {
	var rrset []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		if s, ok := rr.(*dns.RRSIG); ok {
			if s.TypeCovered == qtype {
				sigs = append(sigs, s)
			}
			continue
		}
		if rr.Header().Rrtype == qtype {
			rrset = append(rrset, rr)
		}
	}
	return rrset, sigs
}

func dnskeyRRs(keys []*dns.DNSKEY) []dns.RR {
	out := make([]dns.RR, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

func dsRRs(ds []*dns.DS) []dns.RR {
	out := make([]dns.RR, len(ds))
	for i, d := range ds {
		out[i] = d
	}
	return out
}

func parentZone(zone string) string {
	zone = dns.Fqdn(zone)
	if zone == "." {
		return "."
	}
	i := strings.IndexByte(zone, '.')
	if i < 0 || i+1 >= len(zone) {
		return "."
	}
	return zone[i+1:]
}
