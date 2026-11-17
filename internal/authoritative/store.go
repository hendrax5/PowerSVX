package authoritative

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
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

// IXFRDelta records added/removed RRs between two zone serials.
type IXFRDelta struct {
	FromSerial uint32
	ToSerial   uint32
	Removed    []Record
	Added      []Record
}

const maxIXFRHistory = 64

// Store holds authoritative zones loaded from PostgreSQL (or empty).
type Store struct {
	mu    sync.RWMutex
	zones map[string][]Record
	ixfr  map[string][]IXFRDelta
}

func NewStore() *Store {
	return &Store{
		zones: make(map[string][]Record),
		ixfr:  make(map[string][]IXFRDelta),
	}
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
	oldSer := s.currentSOASerialLocked(zone)
	s.zones[zone] = append(s.zones[zone], rec)
	newSer, _ := s.bumpSOASerialLocked(zone)
	if oldSer > 0 && newSer > oldSer {
		s.appendIXFRLocked(zone, IXFRDelta{FromSerial: oldSer, ToSerial: newSer, Added: []Record{rec}})
	}
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
			oldRec := r
			oldSer := s.currentSOASerialLocked(zone)
			recs[i] = rec
			s.zones[zone] = recs
			newSer, _ := s.bumpSOASerialLocked(zone)
			if oldSer > 0 && newSer > oldSer {
				s.appendIXFRLocked(zone, IXFRDelta{FromSerial: oldSer, ToSerial: newSer, Removed: []Record{oldRec}, Added: []Record{rec}})
			}
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
	kept := make([]Record, 0, len(recs))
	var removed []Record
	for _, r := range recs {
		if config.NormalizeName(r.Name) == name && (qtype == 0 || r.Type == qtype) {
			removed = append(removed, r)
			continue
		}
		kept = append(kept, r)
	}
	s.zones[zone] = kept
	if len(removed) > 0 {
		oldSer := s.currentSOASerialLocked(zone)
		newSer, _ := s.bumpSOASerialLocked(zone)
		if oldSer > 0 && newSer > oldSer {
			s.appendIXFRLocked(zone, IXFRDelta{FromSerial: oldSer, ToSerial: newSer, Removed: removed})
		}
	}
	return len(removed)
}

// DeleteRecordExact removes records matching name+type+content (+prio for MX).
func (s *Store) DeleteRecordExact(zone string, want Record) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	zone = config.NormalizeName(zone)
	want.Name = config.NormalizeName(want.Name)
	want.Content = strings.TrimSpace(want.Content)
	recs := s.zones[zone]
	kept := make([]Record, 0, len(recs))
	var removed []Record
	for _, r := range recs {
		if config.NormalizeName(r.Name) == want.Name &&
			r.Type == want.Type &&
			strings.EqualFold(strings.TrimSpace(r.Content), want.Content) &&
			r.Prio == want.Prio {
			removed = append(removed, r)
			continue
		}
		kept = append(kept, r)
	}
	s.zones[zone] = kept
	if len(removed) > 0 {
		oldSer := s.currentSOASerialLocked(zone)
		newSer, _ := s.bumpSOASerialLocked(zone)
		if oldSer > 0 && newSer > oldSer {
			s.appendIXFRLocked(zone, IXFRDelta{FromSerial: oldSer, ToSerial: newSer, Removed: removed})
		}
	}
	return len(removed)
}

func (s *Store) currentSOASerialLocked(zone string) uint32 {
	for _, r := range s.zones[zone] {
		if r.Type != dns.TypeSOA {
			continue
		}
		parts := strings.Fields(r.Content)
		if len(parts) >= 3 {
			if ser, err := strconv.ParseUint(parts[2], 10, 32); err == nil {
				return uint32(ser)
			}
		}
	}
	return 0
}

func (s *Store) bumpSOASerialLocked(zone string) (uint32, bool) {
	recs := s.zones[zone]
	for i, r := range recs {
		if r.Type != dns.TypeSOA {
			continue
		}
		parts := strings.Fields(r.Content)
		if len(parts) < 7 {
			return 0, false
		}
		serial, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			return 0, false
		}
		serial++
		parts[2] = strconv.FormatUint(serial, 10)
		recs[i].Content = strings.Join(parts, " ")
		s.zones[zone] = recs
		return uint32(serial), true
	}
	return 0, false
}

func (s *Store) appendIXFRLocked(zone string, d IXFRDelta) {
	if s.ixfr == nil {
		s.ixfr = make(map[string][]IXFRDelta)
	}
	hist := append(s.ixfr[zone], d)
	if len(hist) > maxIXFRHistory {
		hist = hist[len(hist)-maxIXFRHistory:]
	}
	s.ixfr[zone] = hist
}

// CurrentSOASerial returns the current SOA serial for zone (0 if none).
func (s *Store) CurrentSOASerial(zone string) uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentSOASerialLocked(config.NormalizeName(zone))
}

// IXFRDeltas returns incremental deltas starting from clientSerial, plus current serial.
// ok=false if history doesn't cover clientSerial (caller should fall back to AXFR).
func (s *Store) IXFRDeltas(zone string, clientSerial uint32) (deltas []IXFRDelta, currentSerial uint32, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	zone = config.NormalizeName(zone)
	cur := s.currentSOASerialLocked(zone)
	if cur == 0 || clientSerial == 0 {
		return nil, cur, false
	}
	if cur == clientSerial || int32(cur-clientSerial) <= 0 {
		return nil, cur, true
	}
	hist := s.ixfr[zone]
	startIdx := -1
	for i, d := range hist {
		if d.FromSerial == clientSerial {
			startIdx = i
			break
		}
	}
	if startIdx < 0 {
		return nil, cur, false
	}
	out := make([]IXFRDelta, len(hist)-startIdx)
	copy(out, hist[startIdx:])
	return out, cur, true
}

// NameExists reports whether any RR exists at name in zone.
func (s *Store) NameExists(zone, name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	zone = config.NormalizeName(zone)
	name = config.NormalizeName(name)
	for _, r := range s.zones[zone] {
		if config.NormalizeName(r.Name) == name {
			return true
		}
	}
	return false
}

// RRSetExists reports whether name+type exists in zone.
func (s *Store) RRSetExists(zone, name string, qtype uint16) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	zone = config.NormalizeName(zone)
	name = config.NormalizeName(name)
	for _, r := range s.zones[zone] {
		if config.NormalizeName(r.Name) == name && r.Type == qtype {
			return true
		}
	}
	return false
}

// BumpSOASerial increments the zone SOA serial (creates none). Returns new serial.
func (s *Store) BumpSOASerial(zone string) (uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	zone = config.NormalizeName(zone)
	recs := s.zones[zone]
	for i, r := range recs {
		if r.Type != dns.TypeSOA {
			continue
		}
		parts := strings.Fields(r.Content)
		if len(parts) < 7 {
			return 0, false
		}
		serial, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			return 0, false
		}
		serial++
		parts[2] = strconv.FormatUint(serial, 10)
		recs[i].Content = strings.Join(parts, " ")
		s.zones[zone] = recs
		return uint32(serial), true
	}
	return 0, false
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
		ip := net.ParseIP(strings.TrimSpace(rec.Content))
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 address")
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("expected IPv4 address for A record")
		}
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip4,
		}, nil
	case dns.TypeAAAA:
		ip := net.ParseIP(strings.TrimSpace(rec.Content))
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address")
		}
		if ip.To4() != nil {
			return nil, fmt.Errorf("expected IPv6 address for AAAA record")
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
	case dns.TypePTR:
		return &dns.PTR{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl},
			Ptr: config.NormalizeName(rec.Content),
		}, nil
	case dns.TypeTXT:
		txt := rec.Content
		if len(txt) >= 2 && strings.HasPrefix(txt, `"`) && strings.HasSuffix(txt, `"`) {
			txt = txt[1 : len(txt)-1]
		}
		var chunks []string
		for len(txt) > 255 {
			chunks = append(chunks, txt[:255])
			txt = txt[255:]
		}
		chunks = append(chunks, txt)
		return &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: chunks,
		}, nil
	case dns.TypeMX:
		return &dns.MX{
			Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
			Preference: rec.Prio,
			Mx:         config.NormalizeName(rec.Content),
		}, nil
	default:
		typName := dns.TypeToString[rec.Type]
		if typName == "" {
			return nil, fmt.Errorf("unsupported record type %d", rec.Type)
		}
		line := fmt.Sprintf("%s %d IN %s %s", name, ttl, typName, strings.TrimSpace(rec.Content))
		return dns.NewRR(line)
	}
}

// ValidateRecord verifies that a Record parses into a valid DNS RR.
func ValidateRecord(rec Record) error {
	rr, err := buildRR(rec)
	if err != nil {
		return err
	}
	if rr == nil {
		return fmt.Errorf("invalid record")
	}
	return nil
}

// ImportBINDZone parses RFC 1035 BIND master zone syntax into []Record.
func ImportBINDZone(zone, masterText string) ([]Record, error) {
	origin := config.NormalizeName(zone)
	zp := dns.NewZoneParser(strings.NewReader(masterText), origin, "")
	var out []Record
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rec, conv := RecordFromRR(rr); conv {
			out = append(out, rec)
		}
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ExportBINDZone renders a zone into RFC 1035 master zone text.
func (s *Store) ExportBINDZone(zone string) (string, bool) {
	recs, ok := s.GetRecords(zone)
	if !ok {
		return "", false
	}
	origin := config.NormalizeName(zone)
	var b strings.Builder
	fmt.Fprintf(&b, "$ORIGIN %s\n$TTL 3600\n", origin)
	for _, rec := range recs {
		if rr := RecordToRR(rec); rr != nil {
			b.WriteString(rr.String())
			b.WriteByte('\n')
		}
	}
	return b.String(), true
}

// ZoneNames returns sorted FQDN names for all unique owners in zone (used by DNSSEC NSEC chain).
func (s *Store) ZoneNames(zone string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	zone = config.NormalizeName(zone)
	seen := map[string]struct{}{zone: {}}
	for _, r := range s.zones[zone] {
		n := config.NormalizeName(r.Name)
		if !strings.HasPrefix(n, "*.") {
			seen[n] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
