package rpz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FeedState is persisted SOA serial for one AXFR RPZ policy.
type FeedState struct {
	Zone      string    `json:"zone"`
	Serial    uint32    `json:"serial"`
	UpdatedAt time.Time `json:"updated_at"`
}

type axfrStateFile struct {
	Feeds map[string]FeedState `json:"feeds"`
}

// AxfrStateStore tracks last successful AXFR/IXFR serials per policy name.
type AxfrStateStore struct {
	mu   sync.Mutex
	path string
	data axfrStateFile
}

func AxfrStatePath(dir string) string {
	if dir == "" {
		dir = "./data"
	}
	return filepath.Join(dir, "rpz-axfr-state.json")
}

func LoadAxfrState(path string) *AxfrStateStore {
	s := &AxfrStateStore{path: path, data: axfrStateFile{Feeds: map[string]FeedState{}}}
	b, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	var f axfrStateFile
	if json.Unmarshal(b, &f) != nil || f.Feeds == nil {
		return s
	}
	s.data = f
	return s
}

func (s *AxfrStateStore) Get(name string) (FeedState, bool) {
	if s == nil {
		return FeedState{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.data.Feeds[name]
	return st, ok
}

func (s *AxfrStateStore) Set(name string, zone string, serial uint32) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Feeds == nil {
		s.data.Feeds = map[string]FeedState{}
	}
	s.data.Feeds[name] = FeedState{Zone: zone, Serial: serial, UpdatedAt: time.Now().UTC()}
	return s.saveLocked()
}

func (s *AxfrStateStore) Delete(name string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Feeds == nil {
		return nil
	}
	delete(s.data.Feeds, name)
	return s.saveLocked()
}

func (s *AxfrStateStore) Prune(keep map[string]bool) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.data.Feeds {
		if !keep[name] {
			delete(s.data.Feeds, name)
		}
	}
	return s.saveLocked()
}

func (s *AxfrStateStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}
