package authoritative

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

// MaxCNAMEChain bounds how many CNAME links one answer follows inside the
// hosted zones.
const MaxCNAMEChain = 8

// Segment is the part of an answer that comes from one zone. A CNAME chain that
// crosses hosted zones has one Segment per zone, so each can be signed by the
// key of the zone it came from.
type Segment struct {
	Zone string
	// Name is the name that was looked up in Zone for this part of the answer.
	Name string
	// Wildcard is the owner of the wildcard record the part was synthesized
	// from ("*.example.com."), or empty when the name has records of its own.
	Wildcard string
	RRs  []dns.RR
}

// Resolution is the outcome of looking a name up in the hosted zones.
type Resolution struct {
	// Segments hold the answer-section records in answer order.
	Segments []Segment
	// Zone and Name are the zone and name of the last lookup made in a hosted zone.
	Zone string
	Name string
	// Exists reports whether Name exists in Zone (own records, an empty
	// non-terminal, or a wildcard that covers it).
	Exists bool
	// Negative is true when the last lookup found neither records of the asked
	// type nor a CNAME: the answer ends in NODATA (Exists) or NXDOMAIN.
	Negative bool
}

// Answer returns every record of the answer section.
func (r Resolution) Answer() []dns.RR {
	var out []dns.RR
	for _, seg := range r.Segments {
		out = append(out, seg.RRs...)
	}
	return out
}

// nodeRecords returns the records the zone holds for name as seen by the view:
// the name's own records, or, when the name does not exist, the records of the
// wildcard at its closest encloser, owned by name (RFC 4592 section 2.1.1). The
// bool reports whether the name exists or is covered by a wildcard.
func nodeRecords(zone, name, viewName string, recs []Record) ([]Record, bool, string) {
	// ancestors[0] is name, the last element is the zone apex.
	ancestors := []string{name}
	for n := name; n != zone; {
		i := strings.IndexByte(n, '.')
		n = n[i+1:]
		if n == "" {
			n = "."
		}
		ancestors = append(ancestors, n)
	}
	best := len(ancestors) - 1 // the apex always exists
	var own []Record
	type wild struct {
		idx int
		rec Record
	}
	var wilds []wild
	for _, rec := range recs {
		if !viewOK(rec.View, viewName) {
			continue
		}
		o := config.NormalizeName(rec.Name)
		if o == name {
			own = append(own, rec)
		}
		// o exists below or at the first ancestor it falls under; every
		// ancestor above it exists as an empty non-terminal at least.
		for i := 0; i < best; i++ {
			a := ancestors[i]
			if o == a || a == "." || strings.HasSuffix(o, "."+a) {
				best = i
				break
			}
		}
		if strings.HasPrefix(o, "*.") {
			for i, a := range ancestors {
				if o[2:] == a {
					wilds = append(wilds, wild{i, rec})
					break
				}
			}
		}
	}
	if best == 0 {
		return own, true, ""
	}
	var out []Record
	for _, w := range wilds {
		if w.idx == best {
			r := w.rec
			r.Name = name
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, false, ""
	}
	return out, true, "*." + ancestors[best]
}

func filterType(recs []Record, qtype uint16) []Record {
	var out []Record
	for _, r := range recs {
		if qtype == dns.TypeANY || r.Type == qtype {
			out = append(out, r)
		}
	}
	return out
}

func buildRRs(recs []Record, geoTag string) []dns.RR {
	var out []dns.RR
	for _, rec := range pickGeo(recs, geoTag) {
		if rr, err := buildRR(rec); err == nil && rr != nil {
			out = append(out, rr)
		}
	}
	return out
}

// cnameApplies reports whether a CNAME at a name answers a query of qtype
// (RFC 1034 section 3.6.2, RFC 2181 section 10.1). CNAME itself is answered as
// asked; RRSIG and NSEC belong to the name; ANY returns what the name holds.
func cnameApplies(qtype uint16) bool {
	switch qtype {
	case dns.TypeCNAME, dns.TypeANY, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
		return false
	}
	return true
}

// Resolve answers qname/qtype from the hosted zones for a client in viewName
// and geoTag. inZone is false when qname is in no hosted zone.
//
// A wildcard record answers only for a name that does not exist, with the
// query name as owner. A name that owns a CNAME and no record of the asked type
// answers with the CNAME; when its target is in a hosted zone the chain is
// followed (at most MaxCNAMEChain links, a loop is cut off) and the target's
// records of the asked type are added. A target outside the hosted zones is
// left to the resolver.
func (s *Store) Resolve(qname string, qtype uint16, viewName, geoTag string) (res Resolution, inZone bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	viewName = strings.ToLower(viewName)
	geoTag = strings.ToUpper(geoTag)
	name := config.NormalizeName(qname)
	zone := s.findZone(name)
	if zone == "" {
		return res, false
	}

	visited := map[string]bool{}
	for links := 0; ; links++ {
		visited[name] = true
		node, exists, wildcard := nodeRecords(zone, name, viewName, s.zones[zone])
		res.Zone, res.Name, res.Exists = zone, name, exists

		if rrs := buildRRs(filterType(node, qtype), geoTag); len(rrs) > 0 {
			res.Segments = append(res.Segments, Segment{Zone: zone, Name: name, Wildcard: wildcard, RRs: rrs})
			return res, true
		}
		var cnames []dns.RR
		if cnameApplies(qtype) {
			cnames = buildRRs(filterType(node, dns.TypeCNAME), geoTag)
		}
		if len(cnames) == 0 {
			res.Negative = true
			return res, true
		}
		cname := cnames[0].(*dns.CNAME)
		res.Segments = append(res.Segments, Segment{Zone: zone, Name: name, Wildcard: wildcard, RRs: []dns.RR{cname}})

		target := config.NormalizeName(cname.Target)
		tz := s.findZone(target)
		if tz == "" || visited[target] || links+1 >= MaxCNAMEChain {
			return res, true
		}
		name, zone = target, tz
		// A followed answer from another zone is a separate segment.
	}
}

// LookupScoped returns the answer-section records for qname/qtype, following
// CNAMEs inside the hosted zones as Resolve does.
func (s *Store) LookupScoped(qname string, qtype uint16, viewName, geoTag string) (rrs []dns.RR, foundZone bool) {
	res, ok := s.Resolve(qname, qtype, viewName, geoTag)
	return res.Answer(), ok
}
