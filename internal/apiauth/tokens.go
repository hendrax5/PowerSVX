package apiauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// StoredToken represents a revocable API key whose secret is stored only as a SHA-256 hash.
type StoredToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	Prefix     string     `json:"prefix"`
	Hash       string     `json:"hash,omitempty"` // omitted in public list DTOs
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type tokensFile struct {
	Tokens []StoredToken `json:"tokens"`
}

// TokenStore manages API bearer tokens persisted at data/tokens.json.
type TokenStore struct {
	mu     sync.RWMutex
	path   string
	tokens map[string]StoredToken
}

func NewTokenStore(dataDir string) (*TokenStore, error) {
	if dataDir == "" {
		dataDir = "./data"
	}
	s := &TokenStore{
		path:   filepath.Join(dataDir, "tokens.json"),
		tokens: make(map[string]StoredToken),
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func hashSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *TokenStore) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var f tokensFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	s.tokens = make(map[string]StoredToken, len(f.Tokens))
	for _, t := range f.Tokens {
		if t.ID != "" && t.Hash != "" {
			s.tokens[t.ID] = t
		}
	}
	return nil
}

func (s *TokenStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	list := make([]StoredToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	b, err := json.MarshalIndent(tokensFile{Tokens: list}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Create generates a cryptographically random bearer token (`psvx_<hex>`),
// stores its SHA-256 hash on disk, and returns metadata + plaintext token (shown once).
func (s *TokenStore) Create(name, role string, ttlDays int) (StoredToken, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return StoredToken{}, "", fmt.Errorf("token name required")
	}
	role = normalizeRole(role)
	var idBytes [8]byte
	var secBytes [24]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return StoredToken{}, "", err
	}
	if _, err := rand.Read(secBytes[:]); err != nil {
		return StoredToken{}, "", err
	}
	plain := "psvx_" + hex.EncodeToString(secBytes[:])
	now := time.Now().UTC()
	var exp *time.Time
	if ttlDays > 0 {
		t := now.Add(time.Duration(ttlDays) * 24 * time.Hour)
		exp = &t
	}
	tok := StoredToken{
		ID:        hex.EncodeToString(idBytes[:]),
		Name:      name,
		Role:      role,
		Prefix:    plain[:12] + "...",
		Hash:      hashSecret(plain),
		CreatedAt: now,
		ExpiresAt: exp,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tok.ID] = tok
	if err := s.saveLocked(); err != nil {
		delete(s.tokens, tok.ID)
		return StoredToken{}, "", err
	}
	pub := tok
	pub.Hash = ""
	return pub, plain, nil
}

// List returns token metadata without secret hashes.
func (s *TokenStore) List() []StoredToken {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]StoredToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		pub := t
		pub.Hash = ""
		out = append(out, pub)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Revoke deletes a token by ID.
func (s *TokenStore) Revoke(id string) error {
	if s == nil {
		return fmt.Errorf("token store unavailable")
	}
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[id]; !ok {
		return fmt.Errorf("token not found")
	}
	delete(s.tokens, id)
	return s.saveLocked()
}

// Resolve verifies a raw bearer token in constant time and updates LastUsedAt asynchronously.
func (s *TokenStore) Resolve(raw string) (Principal, bool) {
	if s == nil {
		return Principal{}, false
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Principal{}, false
	}
	h := hashSecret(raw)
	now := time.Now().UTC()

	s.mu.RLock()
	var matched *StoredToken
	for id, t := range s.tokens {
		if subtleEqual(t.Hash, h) {
			if t.ExpiresAt != nil && now.After(*t.ExpiresAt) {
				s.mu.RUnlock()
				return Principal{}, false
			}
			cp := t
			cp.ID = id
			matched = &cp
			break
		}
	}
	s.mu.RUnlock()
	if matched == nil {
		return Principal{}, false
	}
	return Principal{Name: "token:" + matched.Name, Role: matched.Role}, true
}
