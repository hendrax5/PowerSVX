package apiauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	SessionCookie = "powersvx_session"
	DefaultTTL    = 12 * time.Hour
)

type SessionStore struct {
	mu      sync.RWMutex
	path    string
	ttl     time.Duration
	secure  bool
	byID    map[string]sessionRec
}

type sessionRec struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type sessionsFile struct {
	Sessions []sessionRec `json:"sessions"`
}

func NewSessionStore(dataDir string, ttl time.Duration, secureCookie bool) *SessionStore {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	s := &SessionStore{
		path:   filepath.Join(dataDir, "sessions.json"),
		ttl:    ttl,
		secure: secureCookie,
		byID:   map[string]sessionRec{},
	}
	_ = s.load()
	return s
}

func (s *SessionStore) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var f sessionsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = map[string]sessionRec{}
	for _, rec := range f.Sessions {
		if rec.ExpiresAt.After(now) {
			s.byID[rec.ID] = rec
		}
	}
	return nil
}

func (s *SessionStore) persistLocked() {
	list := make([]sessionRec, 0, len(s.byID))
	now := time.Now()
	for id, rec := range s.byID {
		if rec.ExpiresAt.Before(now) {
			delete(s.byID, id)
			continue
		}
		list = append(list, rec)
	}
	b, err := json.MarshalIndent(sessionsFile{Sessions: list}, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, s.path)
}

func (s *SessionStore) Create(p Principal) (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf[:])
	rec := sessionRec{
		ID:        id,
		Name:      p.Name,
		Role:      p.Role,
		ExpiresAt: time.Now().Add(s.ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[id] = rec
	s.persistLocked()
	return id, nil
}

func (s *SessionStore) Get(id string) (Principal, bool) {
	if id == "" {
		return Principal{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok {
		return Principal{}, false
	}
	if time.Now().After(rec.ExpiresAt) {
		delete(s.byID, id)
		s.persistLocked()
		return Principal{}, false
	}
	return Principal{Name: rec.Name, Role: rec.Role}, true
}

func (s *SessionStore) Delete(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
	s.persistLocked()
}

func (s *SessionStore) SetCookie(w http.ResponseWriter, r *http.Request, id string) {
	secure := s.secure
	if r != nil {
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			secure = true
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   int(s.ttl.Seconds()),
	})
}

func (s *SessionStore) ClearCookie(w http.ResponseWriter, r *http.Request) {
	secure := s.secure
	if r != nil {
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			secure = true
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   -1,
	})
}

func ReadSessionCookie(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}
