package authoritative

import (
	"sort"
	"strings"

	"github.com/powersvx/powersvx/internal/config"
)

// ZoneNameTypes maps every owner name of the zone to the record types that name
// has for a client in viewName and geoTag, which is what LookupScoped would
// answer. Wildcard owners are included under their own name. DNSSEC builds the
// NSEC chain and the type bitmaps from it.
func (s *Store) ZoneNameTypes(zone, viewName, geoTag string) map[string][]uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	zone = config.NormalizeName(zone)
	viewName = strings.ToLower(viewName)
	geoTag = strings.ToUpper(geoTag)

	type key struct {
		name string
		typ  uint16
	}
	groups := map[key][]Record{}
	for _, r := range s.zones[zone] {
		if !viewOK(r.View, viewName) {
			continue
		}
		k := key{config.NormalizeName(r.Name), r.Type}
		groups[k] = append(groups[k], r)
	}
	out := map[string][]uint16{}
	for k, recs := range groups {
		for _, rec := range pickGeo(recs, geoTag) {
			if rr, err := buildRR(rec); err == nil && rr != nil {
				out[k.name] = append(out[k.name], k.typ)
				break
			}
		}
	}
	for _, types := range out {
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	}
	return out
}
