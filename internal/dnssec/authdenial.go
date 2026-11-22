package dnssec

import (
	"bytes"
	"crypto"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Authenticated denial of existence for the Authoritative Zones this process
// signs (RFC 4034 section 4, RFC 4035 section 3.1.3 for NSEC).
//
// The caller hands over every owner name of the zone with the record types
// that name has in the view being answered; this file turns that into the
// canonical chain and picks the records that prove an NXDOMAIN or a NODATA.

// denialTTLFallback is the NSEC TTL when the response carries no SOA.
const denialTTLFallback = 300

// signValidity is how long the signatures made on the fly are valid.
const signValidity = 30 * 24 * time.Hour

// canonicalLabels returns the labels of name as unescaped, lower-cased octets,
// leftmost first, without the root label.
func canonicalLabels(name string) [][]byte {
	name = dns.Fqdn(name)
	if name == "." {
		return nil
	}
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		parts := dns.SplitDomainName(strings.ToLower(name))
		out := make([][]byte, len(parts))
		for i, p := range parts {
			out[i] = []byte(p)
		}
		return out
	}
	var out [][]byte
	for i := 0; i < off; {
		l := int(buf[i])
		if l == 0 {
			break
		}
		lab := bytes.ToLower(buf[i+1 : i+1+l])
		out = append(out, lab)
		i += 1 + l
	}
	return out
}

// canonicalCompare orders two names as RFC 4034 section 6.1 does: compare the
// labels starting from the rightmost one, each as lower-cased octets, and a
// name that runs out of labels sorts before the longer one.
func canonicalCompare(a, b string) int {
	la, lb := canonicalLabels(a), canonicalLabels(b)
	i, j := len(la)-1, len(lb)-1
	for i >= 0 && j >= 0 {
		if c := bytes.Compare(la[i], lb[j]); c != 0 {
			return c
		}
		i--
		j--
	}
	switch {
	case i < 0 && j < 0:
		return 0
	case i < 0:
		return -1
	default:
		return 1
	}
}

// denialZone is the name space of one zone as the denial records need it.
type denialZone struct {
	apex   string
	chain  []string            // names that own records, canonical order
	types  map[string][]uint16 // canonical name -> sorted unique record types
	exists map[string]bool     // chain names plus empty non-terminals
}

// newDenialZone builds the chain from the zone's owner names. Names outside
// the zone are ignored and the apex is always present.
func newDenialZone(apex string, names map[string][]uint16) *denialZone {
	apex = dns.CanonicalName(apex)
	z := &denialZone{apex: apex, types: map[string][]uint16{}, exists: map[string]bool{}}
	add := func(name string, types []uint16) {
		z.types[name] = append(z.types[name], types...)
	}
	add(apex, nil)
	for n, t := range names {
		cn := dns.CanonicalName(n)
		if cn != apex && !dns.IsSubDomain(apex, cn) {
			continue
		}
		add(cn, t)
	}
	for n, t := range z.types {
		z.types[n] = sortUniqueTypes(t)
		z.chain = append(z.chain, n)
		// The name and every name between it and the apex exist; the ones
		// that own no records are the empty non-terminals.
		for p := n; ; p = parentOf(p) {
			z.exists[p] = true
			if p == apex || p == "." {
				break
			}
		}
	}
	sort.Slice(z.chain, func(i, j int) bool { return canonicalCompare(z.chain[i], z.chain[j]) < 0 })
	return z
}

func parentOf(name string) string {
	i, end := dns.NextLabel(name, 0)
	if end || i >= len(name) {
		return "."
	}
	return name[i:]
}

func sortUniqueTypes(in []uint16) []uint16 {
	sorted := append([]uint16(nil), in...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	out := sorted[:0]
	for i, t := range sorted {
		if i == 0 || t != sorted[i-1] {
			out = append(out, t)
		}
	}
	return out
}

// closestEncloser is the longest ancestor of qname that exists in the zone,
// whether it owns records or is an empty non-terminal.
func (z *denialZone) closestEncloser(qname string) string {
	for p := parentOf(qname); ; p = parentOf(p) {
		if z.exists[p] || p == z.apex || p == "." {
			return p
		}
	}
}

// coverIndex is the index in the chain of the last name that sorts at or
// before name. The apex sorts before every name of the zone, so for a name
// inside the zone this is always a valid index.
func (z *denialZone) coverIndex(name string) int {
	i := sort.Search(len(z.chain), func(i int) bool { return canonicalCompare(z.chain[i], name) > 0 })
	if i == 0 {
		return len(z.chain) - 1
	}
	return i - 1
}

// nsecAt builds the NSEC record owned by chain[i].
func (z *denialZone) nsecAt(i int, ttl uint32) *dns.NSEC {
	owner := z.chain[i]
	bitmap := sortUniqueTypes(append(append([]uint16(nil), z.types[owner]...), dns.TypeRRSIG, dns.TypeNSEC))
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
		NextDomain: z.chain[(i+1)%len(z.chain)],
		TypeBitMap: bitmap,
	}
}

// nsecProof returns the NSEC records that prove the negative answer: for
// NXDOMAIN the NSEC covering qname plus the one covering the wildcard at the
// closest encloser, for NODATA the NSEC that matches qname (or, for an empty
// non-terminal, the one that covers it).
func (z *denialZone) nsecProof(qname string, nxdomain bool, ttl uint32) []*dns.NSEC {
	qname = dns.CanonicalName(qname)
	var idx []int
	seen := map[int]bool{}
	add := func(i int) {
		if !seen[i] {
			seen[i] = true
			idx = append(idx, i)
		}
	}
	add(z.coverIndex(qname))
	if nxdomain {
		add(z.coverIndex("*." + z.closestEncloser(qname)))
	}
	out := make([]*dns.NSEC, 0, len(idx))
	for _, i := range idx {
		out = append(out, z.nsecAt(i, ttl))
	}
	return out
}

// negativeTTL is the TTL for denial records: the smaller of the SOA TTL and
// its minimum field (RFC 2308 section 5), as the SOA in the response says.
func negativeTTL(resp *dns.Msg) uint32 {
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			if soa.Minttl < soa.Hdr.Ttl {
				return soa.Minttl
			}
			return soa.Hdr.Ttl
		}
	}
	return denialTTLFallback
}

// rrsigLabels is the RRSIG labels field of an owner name: the label count
// without the root and without a leading wildcard label (RFC 4034 section 3.1.3).
func rrsigLabels(owner string) uint8 {
	n := dns.CountLabel(owner)
	if strings.HasPrefix(owner, "*.") {
		n--
	}
	return uint8(n)
}

// signRRset signs one RRset with the zone signing key.
func signRRset(zone string, rrs []dns.RR, key *dns.DNSKEY, priv crypto.Signer, now time.Time) (*dns.RRSIG, error) {
	h := rrs[0].Header()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
		TypeCovered: h.Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      rrsigLabels(h.Name),
		OrigTtl:     h.Ttl,
		Expiration:  uint32(now.Add(signValidity).Unix()),
		Inception:   uint32(now.Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  zone,
	}
	if err := sig.Sign(priv, rrs); err != nil {
		return nil, fmt.Errorf("sign %s %s: %w", h.Name, dns.TypeToString[h.Rrtype], err)
	}
	return sig, nil
}

// signNSECDenial adds the signed NSEC proof to resp, and signs the SOA that
// accompanies it: a validator rejects a negative answer whose SOA is unsigned.
func (s *Signer) signNSECDenial(zone, qname string, zk *zoneKeys, names map[string][]uint16, now time.Time, resp *dns.Msg) error {
	z := newDenialZone(zone, names)
	// The apex also owns the DNSKEY RRset, which the handler answers from the signer.
	z.types[z.apex] = sortUniqueTypes(append(z.types[z.apex], dns.TypeDNSKEY))

	var soaSet []dns.RR
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeSOA {
			soaSet = append(soaSet, rr)
		}
	}
	ttl := negativeTTL(resp)
	var errs []error
	if len(soaSet) > 0 {
		if sig, err := signRRset(zone, soaSet, zk.ZSK, zk.ZSKPriv, now); err == nil {
			resp.Ns = append(resp.Ns, sig)
		} else {
			errs = append(errs, err)
		}
	}
	for _, n := range z.nsecProof(qname, resp.Rcode == dns.RcodeNameError, ttl) {
		sig, err := signRRset(zone, []dns.RR{n}, zk.ZSK, zk.ZSKPriv, now)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		resp.Ns = append(resp.Ns, n, sig)
	}
	if len(errs) > 0 {
		return fmt.Errorf("dnssec denial for %s: %v", qname, errs)
	}
	return nil
}
