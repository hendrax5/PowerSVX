package acme

import (
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

// ChallengeStore holds DNS-01 TXT values for _acme-challenge names.
type ChallengeStore struct {
	mu  sync.RWMutex
	txt map[string]string // fqdn -> value
}

func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{txt: make(map[string]string)}
}

func (s *ChallengeStore) Present(domain, value string) {
	if s == nil {
		return
	}
	name := challengeName(domain)
	s.mu.Lock()
	s.txt[name] = value
	s.mu.Unlock()
}

func (s *ChallengeStore) CleanUp(domain string) {
	if s == nil {
		return
	}
	name := challengeName(domain)
	s.mu.Lock()
	delete(s.txt, name)
	s.mu.Unlock()
}

func (s *ChallengeStore) LookupTXT(qname string) (string, bool) {
	if s == nil {
		return "", false
	}
	qname = config.NormalizeName(qname)
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.txt[qname]
	return v, ok
}

func (s *ChallengeStore) Count() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.txt)
}

func challengeName(domain string) string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	return config.NormalizeName("_acme-challenge." + d)
}

// TXTAnswer builds a TXT RR if a challenge is present.
func (s *ChallengeStore) TXTAnswer(qname string) dns.RR {
	v, ok := s.LookupTXT(qname)
	if !ok {
		return nil
	}
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: config.NormalizeName(qname), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{v},
	}
}
