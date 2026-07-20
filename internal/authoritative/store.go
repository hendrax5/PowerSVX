package authoritative

import (
	"net"
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
}

// Store holds authoritative zones loaded from PostgreSQL (or empty).
type Store struct {
	mu    sync.RWMutex
	zones map[string][]Record // zone apex -> records
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

func (s *Store) Lookup(qname string, qtype uint16) (rrs []dns.RR, foundZone bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	qname = config.NormalizeName(qname)

	zone := s.findZone(qname)
	if zone == "" {
		return nil, false
	}
	foundZone = true
	recs := s.zones[zone]
	for _, rec := range recs {
		name := config.NormalizeName(rec.Name)
		if name != qname && !wildcardMatch(rec.Name, qname) {
			continue
		}
		if rec.Type != qtype && qtype != dns.TypeANY {
			continue
		}
		rr, err := buildRR(rec)
		if err != nil || rr == nil {
			continue
		}
		rrs = append(rrs, rr)
	}
	return rrs, foundZone
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
	suffix := pattern[1:] // ".example.com."
	return strings.HasSuffix(qname, suffix)
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
