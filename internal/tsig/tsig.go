package tsig

import (
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Store holds named TSIG secrets (miekg/dns format: map[name]base64secret).
type Store struct {
	mu   sync.RWMutex
	keys map[string]string
}

func New() *Store {
	return &Store{keys: make(map[string]string)}
}

func (s *Store) Set(name, secret string) error {
	if s == nil {
		return fmt.Errorf("nil tsig store")
	}
	if name == "" || secret == "" {
		return fmt.Errorf("tsig name and secret required")
	}
	if _, err := base64.StdEncoding.DecodeString(secret); err != nil {
		secret = base64.StdEncoding.EncodeToString([]byte(secret))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[dns.Fqdn(name)] = secret
	return nil
}

func (s *Store) Map() map[string]string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.keys))
	for k, v := range s.keys {
		out[k] = v
	}
	return out
}

func (s *Store) Get(name string) (fqdn, secret string, ok bool) {
	if s == nil || name == "" {
		return "", "", false
	}
	k := dns.Fqdn(name)
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec, ok := s.keys[k]
	return k, sec, ok
}

func (s *Store) Names() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.keys))
	for k := range s.keys {
		out = append(out, k)
	}
	return out
}

func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

// SerialGreater compares two 32-bit SOA serials using RFC 1982 serial number arithmetic.
func SerialGreater(a, b uint32) bool {
	return a != b && int32(a-b) > 0
}

// Auth holds optional RFC 2845 TSIG credentials for outbound DNS messages and zone transfers.
type Auth struct {
	Name      string
	Secret    string // base64 secret
	Algorithm string // default HmacSHA256
}

// Apply signs msg with TSIG when credentials are present and returns the miekg/dns secret map.
func Apply(m *dns.Msg, auth Auth) map[string]string {
	if m == nil || auth.Name == "" || auth.Secret == "" {
		return nil
	}
	name := dns.Fqdn(auth.Name)
	alg := auth.Algorithm
	if alg == "" {
		alg = dns.HmacSHA256
	}
	m.SetTsig(name, alg, 300, time.Now().Unix())
	return map[string]string{name: auth.Secret}
}
