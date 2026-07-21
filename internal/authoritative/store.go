package authoritative

import (
	"net"
	"strings"
	"strconv"
	"sync"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

// Record is an in-memory DNS resource record.
type Record struct {
	Name    string
	Type    uint16
	Content string
	TTL     uint32
	Prio    uint16
	View    string // split-horizon view; empty = all views
	GeoTag  string // country/continent/default; empty = all geos
}

// Store holds authoritative zones loaded from PostgreSQL (or empty).
type Store struct {
	mu    sync.RWMutex
	zones map[string][]Record
}

func NewStore() *Store {
	return &Store{zones: make(map[string][]Record)}
}

func (s *Store) Replace(zones map[string][]Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zones = zones
}

func (s *Store) ZoneCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.zones)
}

// ZoneInfo is a summary for the API.
type ZoneInfo struct {
	Name        string `json:"name"`
	RecordCount int    `json:"record_count"`
}

func (s *Store) ListZones() []ZoneInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ZoneInfo, 0, len(s.zones))
	for name, recs := range s.zones {
		out = append(out, ZoneInfo{Name: name, RecordCount: len(recs)})
	}
	return out
}

func (s *Store) GetRecords(zone string) ([]Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	zone = config.NormalizeName(zone)
	recs, ok := s.zones[zone]
	if !ok {
		return nil, false
	}
	cp := make([]Record, len(recs))
	copy(cp, recs)
	return cp, true
}

func (s *Store) UpsertZone(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = config.NormalizeName(name)
	if _, ok := s.zones[name]; !ok {
		s.zones[name] = nil
	}
}

func (s *Store) DeleteZone(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = config.NormalizeName(name)
	if _, ok := s.zones[name]; !ok {
		return false
	}
	delete(s.zones, name)
	return true
}

func (s *Store) AddRecord(zone string, rec Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	zone = config.NormalizeName(zone)
	rec.Name = config.NormalizeName(rec.Name)
	s.zones[zone] = append(s.zones[zone], rec)
}

func (s *Store) UpdateRecord(zone, oldName string, oldType uint16, rec Record) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	zone = config.NormalizeName(zone)
	oldName = config.NormalizeName(oldName)
	rec.Name = config.NormalizeName(rec.Name)
	recs := s.zones[zone]
	for i, r := range recs {
		if config.NormalizeName(r.Name) == oldName && (oldType == 0 || r.Type == oldType) {
			recs[i] = rec
			s.zones[zone] = recs
			return true
		}
	}
	return false
}

func (s *Store) DeleteRecord(zone, name string, qtype uint16) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	zone = config.NormalizeName(zone)
	name = config.NormalizeName(name)
	recs := s.zones[zone]
	kept := recs[:0]
	n := 0
	for _, r := range recs {
		if config.NormalizeName(r.Name) == name && (qtype == 0 || r.Type == qtype) {
			n++
			continue
		}
		kept = append(kept, r)
	}
	s.zones[zone] = kept
	return n
}

// Lookup returns RRs for qname/qtype filtered by view and geo tag.
func (s *Store) Lookup(qname string, qtype uint16) (rrs []dns.RR, foundZone bool) {
	return s.LookupScoped(qname, qtype, "", "")
}

func (s *Store) LookupScoped(qname string, qtype uint16, viewName, geoTag string) (rrs []dns.RR, foundZone bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	qname = config.NormalizeName(qname)
	viewName = strings.ToLower(viewName)
	geoTag = strings.ToUpper(geoTag)

	zone := s.findZone(qname)
	if zone == "" {
		return nil, false
	}
	foundZone = true

	var candidates []Record
	for _, rec := range s.zones[zone] {
		name := config.NormalizeName(rec.Name)
		if name != qname && !wildcardMatch(rec.Name, qname) {
			continue
		}
		if rec.Type != qtype && qtype != dns.TypeANY {
			continue
		}
		if !viewOK(rec.View, viewName) {
			continue
		}
		candidates = append(candidates, rec)
	}

	picked := pickGeo(candidates, geoTag)
	for _, rec := range picked {
		rr, err := buildRR(rec)
		if err != nil || rr == nil {
			continue
		}
		rrs = append(rrs, rr)
	}
	return rrs, foundZone
}

func viewOK(recView, clientView string) bool {
	recView = strings.ToLower(strings.TrimSpace(recView))
	if recView == "" || recView == "*" {
		return true
	}
	if clientView == "" {
		return recView == "default"
	}
	return recView == clientView
}

// pickGeo prefers records matching geoTag, else continent-less country, else "default"/empty.
func pickGeo(recs []Record, geoTag string) []Record {
	if len(recs) == 0 {
		return nil
	}
	geoTag = strings.ToUpper(strings.TrimSpace(geoTag))
	var exact, def, untagged []Record
	for _, r := range recs {
		tag := strings.ToUpper(strings.TrimSpace(r.GeoTag))
		switch {
		case tag == "" || tag == "*":
			untagged = append(untagged, r)
		case tag == "DEFAULT":
			def = append(def, r)
		case geoTag != "" && tag == geoTag:
			exact = append(exact, r)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	if len(def) > 0 {
		return def
	}
	return untagged
}

func (s *Store) FindZone(qname string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findZone(config.NormalizeName(qname))
}

func (s *Store) findZone(qname string) string {
	best := ""
	for z := range s.zones {
		if qname == z || strings.HasSuffix(qname, "."+z) || strings.HasSuffix(qname, z) {
			if len(z) > len(best) {
				best = z
			}
		}
	}
	return best
}

func wildcardMatch(pattern, qname string) bool {
	pattern = config.NormalizeName(pattern)
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:]
	return strings.HasSuffix(qname, suffix)
}

// RecordToRR converts a store record to a wire RR (nil if unsupported/invalid).
func RecordToRR(rec Record) dns.RR {
	rr, err := buildRR(rec)
	if err != nil || rr == nil {
		return nil
	}
	return rr
}

func buildRR(rec Record) (dns.RR, error) {
	name := config.NormalizeName(rec.Name)
	ttl := rec.TTL
	if ttl == 0 {
		ttl = 3600
	}
	switch rec.Type {
	case dns.TypeA:
		ip := net.ParseIP(rec.Content)
		if ip == nil {
			return nil, nil
		}
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip.To4(),
		}, nil
	case dns.TypeAAAA:
		ip := net.ParseIP(rec.Content)
		if ip == nil {
			return nil, nil
		}
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: ip.To16(),
		}, nil
	case dns.TypeCNAME:
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: config.NormalizeName(rec.Content),
		}, nil
	case dns.TypeNS:
		return &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
			Ns:  config.NormalizeName(rec.Content),
		}, nil
	case dns.TypeTXT:
		return &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{rec.Content},
		}, nil
	case dns.TypeMX:
		return &dns.MX{
			Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
			Preference: rec.Prio,
			Mx:         config.NormalizeName(rec.Content),
		}, nil
	default:
		line := name + " " + dns.TypeToString[rec.Type] + " " + rec.Content
		return dns.NewRR(line)
	}
}


func TypeFromString(s string) uint16 {
	if t, ok := dns.StringToType[strings.ToUpper(s)]; ok {
		return t
	}
	return dns.TypeNone
}

// ReplaceZoneRecords replaces all records for one zone (creates the zone if missing).
func (s *Store) ReplaceZoneRecords(zone string, recs []Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	zone = config.NormalizeName(zone)
	cp := make([]Record, len(recs))
	copy(cp, recs)
	for i := range cp {
		cp[i].Name = config.NormalizeName(cp[i].Name)
	}
	s.zones[zone] = cp
}

// RecordFromRR converts a wire RR into a store record (skips OPT).
func RecordFromRR(rr dns.RR) (Record, bool) {
	if rr == nil {
		return Record{}, false
	}
	h := rr.Header()
	if h.Rrtype == dns.TypeOPT {
		return Record{}, false
	}
	rec := Record{Name: h.Name, Type: h.Rrtype, TTL: h.Ttl}
	switch v := rr.(type) {
	case *dns.A:
		if v.A != nil {
			rec.Content = v.A.String()
		}
	case *dns.AAAA:
		if v.AAAA != nil {
			rec.Content = v.AAAA.String()
		}
	case *dns.CNAME:
		rec.Content = v.Target
	case *dns.NS:
		rec.Content = v.Ns
	case *dns.TXT:
		rec.Content = strings.Join(v.Txt, "")
	case *dns.MX:
		rec.Content = v.Mx
		rec.Prio = v.Preference
	case *dns.SOA:
		rec.Content = strings.Join([]string{
			v.Ns, v.Mbox,
			strconv.FormatUint(uint64(v.Serial), 10),
			strconv.FormatUint(uint64(v.Refresh), 10),
			strconv.FormatUint(uint64(v.Retry), 10),
			strconv.FormatUint(uint64(v.Expire), 10),
			strconv.FormatUint(uint64(v.Minttl), 10),
		}, " ")
	case *dns.PTR:
		rec.Content = v.Ptr
	case *dns.SRV:
		rec.Content = strings.Join([]string{
			strconv.FormatUint(uint64(v.Priority), 10),
			strconv.FormatUint(uint64(v.Weight), 10),
			strconv.FormatUint(uint64(v.Port), 10),
			v.Target,
		}, " ")
		rec.Prio = v.Priority
	default:
		fields := strings.Fields(rr.String())
		if len(fields) < 5 {
			return Record{}, false
		}
		rec.Content = strings.Join(fields[4:], " ")
	}
	if rec.Content == "" && rec.Type != dns.TypeTXT {
		return Record{}, false
	}
	return rec, true
}