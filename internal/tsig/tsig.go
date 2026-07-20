package tsig

import (
	"encoding/base64"
	"fmt"
	"sync"

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

func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}
