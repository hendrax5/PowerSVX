package rpz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FeedState is persisted sync status for one AXFR RPZ policy.
type FeedState struct {
	Zone       string    `json:"zone"`
	Serial     uint32    `json:"serial"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastMode   string    `json:"last_mode,omitempty"`   // full_axfr | ixfr | skipped | failed
	LastError  string    `json:"last_error,omitempty"`
	LastMaster string    `json:"last_master,omitempty"`
	OK         bool      `json:"ok"`
}

// AxfrEvent is a short sync log line for the UI.
type AxfrEvent struct {
	Time    time.Time `json:"time"`
	Feed    string    `json:"feed"`
	Level   string    `json:"level"` // info | warn | error
	Message string    `json:"message"`
}

type axfrStateFile struct {
	Feeds  map[string]FeedState `json:"feeds"`
	Events []AxfrEvent          `json:"events,omitempty"`
}

const maxAxfrEvents = 40

// AxfrStateStore tracks last AXFR/IXFR serials and recent sync events.
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

// Snapshot returns a copy of feed states and recent events for the API/UI.
func (s *AxfrStateStore) Snapshot() (map[string]FeedState, []AxfrEvent) {
	if s == nil {
		return map[string]FeedState{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	feeds := make(map[string]FeedState, len(s.data.Feeds))
	for k, v := range s.data.Feeds {
		if v.LastMode == "" && v.Serial > 0 {
			v.OK = true
			v.LastMode = "full_axfr"
		}
		feeds[k] = v
	}
	ev := append([]AxfrEvent(nil), s.data.Events...)
	return feeds, ev
}

// PutSuccess records a successful sync (full AXFR, IXFR, or skipped).
func (s *AxfrStateStore) PutSuccess(name, zone, mode, master string, serial uint32, msg string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Feeds == nil {
		s.data.Feeds = map[string]FeedState{}
	}
	s.data.Feeds[name] = FeedState{
		Zone:       zone,
		Serial:     serial,
		UpdatedAt:  time.Now().UTC(),
		LastMode:   mode,
		LastError:  "",
		LastMaster: master,
		OK:         true,
	}
	s.appendEventLocked(name, "info", msg)
	return s.saveLocked()
}

// PutFailure records a failed sync without clearing the last good serial.
func (s *AxfrStateStore) PutFailure(name, zone, master, errMsg string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Feeds == nil {
		s.data.Feeds = map[string]FeedState{}
	}
	prev := s.data.Feeds[name]
	prev.Zone = zone
	if master != "" {
		prev.LastMaster = master
	}
	prev.UpdatedAt = time.Now().UTC()
	prev.LastMode = "failed"
	prev.LastError = errMsg
	prev.OK = false
	s.data.Feeds[name] = prev
	s.appendEventLocked(name, "error", errMsg)
	return s.saveLocked()
}

// Set is kept for callers that only know serial (treated as full_axfr success).
func (s *AxfrStateStore) Set(name string, zone string, serial uint32) error {
	return s.PutSuccess(name, zone, "full_axfr", "", serial, "AXFR ok · serial "+itoa(serial))
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

func (s *AxfrStateStore) appendEventLocked(feed, level, msg string) {
	ev := AxfrEvent{Time: time.Now().UTC(), Feed: feed, Level: level, Message: msg}
	s.data.Events = append(s.data.Events, ev)
	if len(s.data.Events) > maxAxfrEvents {
		s.data.Events = s.data.Events[len(s.data.Events)-maxAxfrEvents:]
	}
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

func itoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}
