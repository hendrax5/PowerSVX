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

// signInceptionSkew backdates the inception of signatures so a validator whose
// clock runs a little behind does not see them as not yet valid (RFC 6781
// section 4.4.2.1).
const signInceptionSkew = time.Hour

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
	// The apex also owns the DNSKEY RRset, which the handler answers from the signer.
	add(apex, []uint16{dns.TypeDNSKEY})
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
// non-terminal, the one that covers it; for a name that exists only through a
// wildcard, the NSEC covering the name and the one matching the wildcard).
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
	if nxdomain || !z.exists[qname] {
		// NXDOMAIN, or NODATA for a name that only a wildcard makes exist: the
		// wildcard at the closest encloser is covered, or matched when it exists
		// (RFC 4035 sections 3.1.3.2 and 3.1.3.4).
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
		Inception:   uint32(now.Add(-signInceptionSkew).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  zone,
	}
	if err := sig.Sign(priv, rrs); err != nil {
		return nil, fmt.Errorf("sign %s %s: %w", h.Name, dns.TypeToString[h.Rrtype], err)
	}
	return sig, nil
}

// signNegative attaches the proof to resp and signs it and the SOA that
// accompanies it: a validator rejects a negative answer whose SOA is unsigned.
func signNegative(zone string, zk *zoneKeys, now time.Time, resp *dns.Msg, proof []dns.RR) error {
	var soaSet []dns.RR
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeSOA {
			soaSet = append(soaSet, rr)
		}
	}
	var errs []error
	if len(soaSet) > 0 {
		if sig, err := signRRset(zone, soaSet, zk.ZSK, zk.ZSKPriv, now); err == nil {
			resp.Ns = append(resp.Ns, sig)
		} else {
			errs = append(errs, err)
		}
	}
	for _, rr := range proof {
		sig, err := signRRset(zone, []dns.RR{rr}, zk.ZSK, zk.ZSKPriv, now)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		resp.Ns = append(resp.Ns, rr, sig)
	}
	if len(errs) > 0 {
		return fmt.Errorf("dnssec denial incomplete: %v", errs)
	}
	return nil
}

// signNSECDenial adds the signed NSEC proof for an NSEC-signed zone.
func (s *Signer) signNSECDenial(zone, qname string, zk *zoneKeys, names map[string][]uint16, now time.Time, resp *dns.Msg) error {
	z := newDenialZone(zone, names)
	var proof []dns.RR
	for _, n := range z.nsecProof(qname, resp.Rcode == dns.RcodeNameError, negativeTTL(resp)) {
		proof = append(proof, n)
	}
	return signNegative(zone, zk, now, resp, proof)
}

// NSEC3 (RFC 5155). The hash algorithm is SHA-1, there is no opt-out, and the
// number of additional iterations is fixed; the salt is the zone policy's.
const (
	nsec3Iterations uint16 = 1
	// nsec3DefaultSalt is the salt of a zone whose policy has NSEC3 but no salt.
	nsec3DefaultSalt = "a1b2c3d4"
)

// nsec3Entry is one record of the NSEC3 chain.
type nsec3Entry struct {
	hash  string // base32hex, upper case; sorts as the hash octets do
	types []uint16
}

type nsec3Chain struct {
	zone    string
	salt    string
	entries []nsec3Entry // sorted by hash
}

func nsec3Hash(name, salt string) string {
	return dns.HashName(name, dns.SHA1, nsec3Iterations, salt)
}

// nsec3Chain hashes every name of the zone, the apex and the empty
// non-terminals included, and sorts the result by hash.
func (z *denialZone) nsec3Chain(salt string) *nsec3Chain {
	c := &nsec3Chain{zone: z.apex, salt: salt}
	for name := range z.exists {
		if name != z.apex && !dns.IsSubDomain(z.apex, name) {
			continue
		}
		var types []uint16
		if owned, ok := z.types[name]; ok {
			types = append(types, owned...)
			types = append(types, dns.TypeRRSIG)
		}
		c.entries = append(c.entries, nsec3Entry{hash: nsec3Hash(name, salt), types: sortUniqueTypes(types)})
	}
	sort.Slice(c.entries, func(i, j int) bool { return c.entries[i].hash < c.entries[j].hash })
	return c
}

// coverIndex is the index of the last entry whose hash sorts before h; a hash
// smaller than all of them is covered by the last record, which wraps.
func (c *nsec3Chain) coverIndex(h string) int {
	i := sort.Search(len(c.entries), func(i int) bool { return c.entries[i].hash >= h })
	if i == 0 {
		return len(c.entries) - 1
	}
	return i - 1
}

func (c *nsec3Chain) indexOf(h string) (int, bool) {
	i := sort.Search(len(c.entries), func(i int) bool { return c.entries[i].hash >= h })
	return i, i < len(c.entries) && c.entries[i].hash == h
}

func (c *nsec3Chain) record(i int, ttl uint32) *dns.NSEC3 {
	e := c.entries[i]
	return &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: e.hash + "." + c.zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: ttl},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: nsec3Iterations,
		SaltLength: uint8(len(c.salt) / 2),
		Salt:       c.salt,
		HashLength: 20,
		NextDomain: c.entries[(i+1)%len(c.entries)].hash,
		TypeBitMap: e.types,
	}
}

// matchOrCover is the record that has hash h as its owner, or else the one
// that covers h.
func (c *nsec3Chain) matchOrCover(h string) int {
	if i, ok := c.indexOf(h); ok {
		return i
	}
	return c.coverIndex(h)
}

// nsec3Proof returns the records of RFC 5155 sections 7.2.1 to 7.2.4. For
// NODATA: the record matching qname. For NXDOMAIN, the closest encloser proof:
// the record matching the closest encloser, the one covering the next closer
// name and the one covering the wildcard at the closest encloser.
func (z *denialZone) nsec3Proof(qname, salt string, nxdomain bool, ttl uint32) []*dns.NSEC3 {
	qname = dns.CanonicalName(qname)
	c := z.nsec3Chain(salt)
	var idx []int
	seen := map[int]bool{}
	add := func(i int) {
		if !seen[i] {
			seen[i] = true
			idx = append(idx, i)
		}
	}
	if !nxdomain && z.exists[qname] {
		add(c.matchOrCover(nsec3Hash(qname, salt)))
	} else {
		// NXDOMAIN, or NODATA for a name that only a wildcard makes exist (RFC 5155
		// section 7.2.5): the closest encloser proof, whose wildcard record is the
		// match for an existing wildcard.
		ce := z.closestEncloser(qname)
		add(c.matchOrCover(nsec3Hash(ce, salt)))
		add(c.matchOrCover(nsec3Hash(nextCloser(qname, ce), salt)))
		add(c.matchOrCover(nsec3Hash("*."+ce, salt)))
	}
	out := make([]*dns.NSEC3, 0, len(idx))
	for _, i := range idx {
		out = append(out, c.record(i, ttl))
	}
	return out
}

// nextCloser is the name one label longer than the closest encloser on the way
// to qname.
func nextCloser(qname, ce string) string {
	q, c := dns.SplitDomainName(qname), dns.CountLabel(ce)
	return dns.Fqdn(strings.Join(q[len(q)-c-1:], "."))
}

// signNSEC3Denial adds the signed NSEC3 proof for an NSEC3-signed zone.
func (s *Signer) signNSEC3Denial(zone, qname string, zk *zoneKeys, names map[string][]uint16, now time.Time, resp *dns.Msg) error {
	salt := zk.Policy.Salt
	if salt == "" {
		salt = nsec3DefaultSalt
	}
	z := newDenialZone(zone, names)
	var proof []dns.RR
	for _, n := range z.nsec3Proof(qname, salt, resp.Rcode == dns.RcodeNameError, negativeTTL(resp)) {
		proof = append(proof, n)
	}
	return signNegative(zone, zk, now, resp, proof)
}

// SignWildcardExpansion adds the proof that qname does not exist to an answer
// that was synthesized from a wildcard, when the request has DO set: the NSEC
// covering qname (RFC 4035 section 3.1.3.3), or for NSEC3 the closest encloser
// proof, the record matching the closest encloser and the one covering the next
// closer name (RFC 5155 section 7.2.6). Records already in the authority section
// are not added twice.
func (s *Signer) SignWildcardExpansion(zone, qname string, names map[string][]uint16, req, resp *dns.Msg) error {
	if s == nil || resp == nil {
		return nil
	}
	zone = dns.CanonicalName(zone)
	zk, err := s.load(zone)
	if err != nil {
		return nil
	}
	if req == nil {
		return nil
	}
	if opt := req.IsEdns0(); opt == nil || !opt.Do() {
		return nil
	}
	qname = dns.CanonicalName(qname)
	z := newDenialZone(zone, names)
	ttl := negativeTTL(resp)
	var proof []dns.RR
	if zk.Policy.NSEC3 {
		salt := zk.Policy.Salt
		if salt == "" {
			salt = nsec3DefaultSalt
		}
		c := z.nsec3Chain(salt)
		ce := z.closestEncloser(qname)
		for _, h := range []string{ce, nextCloser(qname, ce)} {
			proof = append(proof, c.record(c.matchOrCover(nsec3Hash(h, salt)), ttl))
		}
	} else {
		proof = append(proof, z.nsecAt(z.coverIndex(qname), ttl))
	}
	have := map[string]bool{}
	for _, rr := range resp.Ns {
		have[dns.CanonicalName(rr.Header().Name)+"/"+dns.TypeToString[rr.Header().Rrtype]] = true
	}
	var fresh []dns.RR
	for _, rr := range proof {
		k := dns.CanonicalName(rr.Header().Name) + "/" + dns.TypeToString[rr.Header().Rrtype]
		if !have[k] {
			have[k] = true
			fresh = append(fresh, rr)
		}
	}
	return signNegative(zone, zk, time.Now().UTC(), resp, fresh)
}
