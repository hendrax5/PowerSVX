package dnssec

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// validateDenial proves a negative answer (NXDOMAIN or NODATA) using signed
// NSEC/NSEC3 records in the authority section (secure denial of existence).
func (v *Validator) validateDenial(msg *dns.Msg, qname string, qtype uint16) (Status, error) {
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	var sigs []*dns.RRSIG
	for _, rr := range msg.Ns {
		switch t := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, t)
		case *dns.NSEC3:
			nsec3s = append(nsec3s, t)
		case *dns.RRSIG:
			if t.TypeCovered == dns.TypeNSEC || t.TypeCovered == dns.TypeNSEC3 {
				sigs = append(sigs, t)
			}
		}
	}
	if len(nsecs) == 0 && len(nsec3s) == 0 {
		return Insecure, nil // no proof records (unsigned or minimal)
	}
	if len(sigs) == 0 {
		return Insecure, nil
	}
	signer := strings.ToLower(sigs[0].SignerName)
	keys, err := v.fetchKeys(signer, 0)
	if err != nil {
		if isInsecure(err) {
			return Insecure, nil
		}
		return Bogus, err
	}
	// Every NSEC/NSEC3 record we might rely on must be validly signed.
	if !verifyDenialRecords(msg.Ns, sigs, keys) {
		return Bogus, fmt.Errorf("dnssec: denial records not validly signed for %s", qname)
	}

	nxdomain := msg.Rcode == dns.RcodeNameError
	if len(nsecs) > 0 && proveNSEC(nsecs, qname, qtype, nxdomain) {
		return Secure, nil
	}
	if len(nsec3s) > 0 && proveNSEC3(nsec3s, qname, qtype, nxdomain) {
		return Secure, nil
	}
	return Bogus, fmt.Errorf("dnssec: denial of existence not proven for %s", qname)
}

func isInsecure(err error) bool { return err == errInsecure }

// verifyDenialRecords checks each NSEC/NSEC3 record verifies against the keys.
func verifyDenialRecords(ns []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY) bool {
	verifyOne := func(rr dns.RR, covered uint16) bool {
		owner := strings.ToLower(rr.Header().Name)
		for _, s := range sigs {
			if s.TypeCovered != covered || strings.ToLower(s.Hdr.Name) != owner {
				continue
			}
			if verifyRRSet([]dns.RR{rr}, []*dns.RRSIG{s}, keys) {
				return true
			}
		}
		return false
	}
	for _, rr := range ns {
		switch rr.(type) {
		case *dns.NSEC:
			if !verifyOne(rr, dns.TypeNSEC) {
				return false
			}
		case *dns.NSEC3:
			if !verifyOne(rr, dns.TypeNSEC3) {
				return false
			}
		}
	}
	return true
}

// --- NSEC proofs ---

func proveNSEC(nsecs []*dns.NSEC, qname string, qtype uint16, nxdomain bool) bool {
	if nxdomain {
		for _, n := range nsecs {
			if nsecCovers(n.Hdr.Name, n.NextDomain, qname) {
				return true
			}
		}
		return false
	}
	// NODATA: an NSEC owned by qname must lack qtype (and CNAME).
	for _, n := range nsecs {
		if canonKey(n.Hdr.Name) == canonKey(qname) {
			if !typeInBitmap(n.TypeBitMap, qtype) && !typeInBitmap(n.TypeBitMap, dns.TypeCNAME) {
				return true
			}
		}
	}
	return false
}

// --- NSEC3 proofs ---

func proveNSEC3(nsec3s []*dns.NSEC3, qname string, qtype uint16, nxdomain bool) bool {
	if !nxdomain {
		// NODATA: NSEC3 matching qname must lack qtype.
		for _, n := range nsec3s {
			if n.Match(qname) && !typeInBitmap(n.TypeBitMap, qtype) {
				return true
			}
		}
		return false
	}
	// NXDOMAIN: closest-encloser proof. Find the longest existing ancestor that
	// matches an NSEC3; the next-closer name below it must be covered.
	anc := ancestors(qname)
	ceIdx := -1
	for i := 1; i < len(anc); i++ {
		if matchAny(nsec3s, anc[i]) {
			ceIdx = i
			break
		}
	}
	if ceIdx <= 0 {
		return false
	}
	nextCloser := anc[ceIdx-1]
	return coverAny(nsec3s, nextCloser)
}

func matchAny(nsec3s []*dns.NSEC3, name string) bool {
	for _, n := range nsec3s {
		if n.Match(name) {
			return true
		}
	}
	return false
}

func coverAny(nsec3s []*dns.NSEC3, name string) bool {
	for _, n := range nsec3s {
		if n.Cover(name) {
			return true
		}
	}
	return false
}

// --- helpers ---

func typeInBitmap(bitmap []uint16, t uint16) bool {
	for _, x := range bitmap {
		if x == t {
			return true
		}
	}
	return false
}

func ancestors(name string) []string {
	name = dns.Fqdn(strings.ToLower(name))
	out := []string{name}
	for {
		i := strings.IndexByte(name, '.')
		if i < 0 || i+1 >= len(name) {
			break
		}
		name = name[i+1:]
		out = append(out, name)
		if name == "." {
			break
		}
	}
	return out
}

func canonKey(name string) string {
	name = strings.ToLower(strings.TrimSuffix(dns.Fqdn(name), "."))
	if name == "" {
		return ""
	}
	labels := strings.Split(name, ".")
	var b strings.Builder
	for i := len(labels) - 1; i >= 0; i-- {
		b.WriteString(labels[i])
		b.WriteByte(0)
	}
	return b.String()
}

func nsecCovers(owner, next, qname string) bool {
	o, n, q := canonKey(owner), canonKey(next), canonKey(qname)
	if q == o {
		return false
	}
	if o < n {
		return o < q && q < n
	}
	return q > o || q < n // wraparound at apex
}
