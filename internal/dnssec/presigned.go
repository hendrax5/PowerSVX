package dnssec

import (
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Serving a zone that was received already signed (a Secondary Zone, ADR-0004).
// Nothing is signed here: the NSEC or NSEC3 records and their RRSIGs are data of
// the zone. What this file does is pick, from the chain the zone holds, the
// records that prove a negative answer, by the rules of RFC 4035 section 3.1.3
// and RFC 5155 section 7.2.

// ProofKind says which negative answer, or answer synthesized from a wildcard,
// a proof is wanted for.
type ProofKind int

const (
	// ProofNXDOMAIN: the name does not exist.
	ProofNXDOMAIN ProofKind = iota
	// ProofNODATA: the name exists (or only a wildcard makes it exist) and has no
	// record of the asked type.
	ProofNODATA
	// ProofWildcardExpansion: the name does not exist, and the answer was made
	// from a wildcard.
	ProofWildcardExpansion
)

// PresignedProof returns the records of chain (NSEC or NSEC3 records of the
// zone, all of them) that prove the negative answer for qname. dataNames are the
// owner names of the zone's ordinary records, from which the names that exist
// (empty non-terminals included) follow. An NSEC3 chain is recognised by holding
// NSEC3 records; its hash parameters are those of its records. The result is
// empty when the zone holds no chain.
func PresignedProof(zone, qname string, kind ProofKind, dataNames []string, chain []dns.RR) []dns.RR {
	zone, qname = dns.CanonicalName(zone), dns.CanonicalName(qname)
	z := &denialZone{apex: zone, exists: map[string]bool{zone: true}}
	for _, n := range dataNames {
		cn := dns.CanonicalName(n)
		if cn != zone && !dns.IsSubDomain(zone, cn) {
			continue
		}
		for p := cn; ; p = parentOf(p) {
			z.exists[p] = true
			if p == zone || p == "." {
				break
			}
		}
	}

	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, rr := range chain {
		switch v := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, v)
		case *dns.NSEC3:
			nsec3s = append(nsec3s, v)
		}
	}
	switch {
	case len(nsec3s) > 0:
		return presignedNSEC3(z, qname, kind, nsec3s)
	case len(nsecs) > 0:
		return presignedNSEC(z, qname, kind, nsecs)
	}
	return nil
}

func presignedNSEC(z *denialZone, qname string, kind ProofKind, nsecs []*dns.NSEC) []dns.RR {
	sort.Slice(nsecs, func(i, j int) bool { return canonicalCompare(nsecs[i].Hdr.Name, nsecs[j].Hdr.Name) < 0 })
	for _, n := range nsecs {
		z.chain = append(z.chain, dns.CanonicalName(n.Hdr.Name))
	}
	var out []dns.RR
	seen := map[int]bool{}
	add := func(name string) {
		i := z.coverIndex(name)
		if !seen[i] {
			seen[i] = true
			out = append(out, nsecs[i])
		}
	}
	add(qname)
	if kind == ProofNXDOMAIN || kind == ProofNODATA && !z.exists[qname] {
		add("*." + z.closestEncloser(qname))
	}
	return out
}

func presignedNSEC3(z *denialZone, qname string, kind ProofKind, nsec3s []*dns.NSEC3) []dns.RR {
	first := nsec3s[0]
	hash := func(name string) string {
		return strings.ToUpper(dns.HashName(name, first.Hash, first.Iterations, first.Salt))
	}
	type entry struct {
		hash string
		rr   *dns.NSEC3
	}
	entries := make([]entry, 0, len(nsec3s))
	for _, n := range nsec3s {
		owner := n.Hdr.Name
		if i := strings.IndexByte(owner, '.'); i > 0 {
			owner = owner[:i]
		}
		entries = append(entries, entry{strings.ToUpper(owner), n})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].hash < entries[j].hash })
	c := &nsec3Chain{zone: z.apex}
	for _, e := range entries {
		c.entries = append(c.entries, nsec3Entry{hash: e.hash})
	}

	var out []dns.RR
	seen := map[int]bool{}
	add := func(name string) {
		i := c.matchOrCover(hash(name))
		if !seen[i] {
			seen[i] = true
			out = append(out, entries[i].rr)
		}
	}
	switch {
	case kind == ProofNODATA && z.exists[qname]:
		add(qname)
	case kind == ProofWildcardExpansion:
		ce := z.closestEncloser(qname)
		add(ce)
		add(nextCloser(qname, ce))
	default:
		ce := z.closestEncloser(qname)
		add(ce)
		add(nextCloser(qname, ce))
		add("*." + ce)
	}
	return out
}
