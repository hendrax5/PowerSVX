package authoritative

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

// SetKey names an RRset: an owner name (lower case, absolute) and a type.
type SetKey struct {
	Name string
	Type uint16
}

// RecordsScoped returns the records of zone a client in viewName and geoTag
// would be answered from: for every RRset the records of the view that
// match the geo tag the way a query's answer picks them. The false result means
// the zone does not exist. A signed zone is transferred in this form, since a
// signature covers one RRset and a secondary has no views.
func (s *Store) RecordsScoped(zone, viewName, geoTag string) ([]Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	zone = config.NormalizeName(zone)
	recs, ok := s.zones[zone]
	if !ok {
		return nil, false
	}
	viewName = strings.ToLower(viewName)
	geoTag = strings.ToUpper(geoTag)
	groups := map[SetKey][]Record{}
	var order []SetKey
	for _, r := range recs {
		if !viewOK(r.View, viewName) {
			continue
		}
		k := SetKey{config.NormalizeName(r.Name), r.Type}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	out := make([]Record, 0, len(recs))
	for _, k := range order {
		out = append(out, pickGeo(groups[k], geoTag)...)
	}
	return out, true
}

// SignaturesFor returns the RRSIG records zone holds for the RRsets in want:
// zone data of a zone that was received signed.
func (s *Store) SignaturesFor(zone string, want map[SetKey]bool) map[SetKey][]dns.RR {
	owners := map[string]bool{}
	for k := range want {
		owners[k.Name] = true
	}
	s.mu.RLock()
	var cands []Record
	for _, r := range s.zones[config.NormalizeName(zone)] {
		if r.Type == dns.TypeRRSIG && owners[config.NormalizeName(r.Name)] {
			cands = append(cands, r)
		}
	}
	s.mu.RUnlock()
	out := map[SetKey][]dns.RR{}
	for _, r := range cands {
		rr := RecordToRR(r)
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		k := SetKey{config.NormalizeName(r.Name), sig.TypeCovered}
		if want[k] {
			out[k] = append(out[k], rr)
		}
	}
	return out
}

// DenialData returns what the denial proof of a zone received signed is made
// from: the owner names of its ordinary records, and its NSEC and NSEC3 records.
func (s *Store) DenialData(zone string) (names []string, chain []dns.RR) {
	s.mu.RLock()
	var cands []Record
	seen := map[string]bool{}
	for _, r := range s.zones[config.NormalizeName(zone)] {
		switch r.Type {
		case dns.TypeNSEC, dns.TypeNSEC3:
			cands = append(cands, r)
		case dns.TypeRRSIG:
		default:
			n := config.NormalizeName(r.Name)
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	s.mu.RUnlock()
	for _, r := range cands {
		if rr := RecordToRR(r); rr != nil {
			chain = append(chain, rr)
		}
	}
	return names, chain
}
