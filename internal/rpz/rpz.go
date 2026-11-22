package rpz

import (
	"sync"
	"sync/atomic"
	"time"
)

// Action for a matched domain.
type Action string

const (
	ActionNXDOMAIN Action = "nxdomain"
	ActionNODATA   Action = "nodata"
	ActionPass     Action = "pass"
	ActionRedirect Action = "redirect" // sinkhole A/AAAA to Target (IP)
	ActionCNAME    Action = "cname"    // CNAME to Target (hostname)
)

// Engine tracks the Filter feed sync of the Control Plane: whether filtering is
// enabled, whether a sync is running, its last result, and the persisted
// AXFR/IXFR serials. It holds no domains; the Filter lives in the dnsdist CDB.
type Engine struct {
	mu         sync.RWMutex
	enabled    bool
	loading    atomic.Bool
	lastErr    atomic.Value // string
	lastLoaded atomic.Value // time.Time
	axfrState  *AxfrStateStore
}

// LoadStatus is exposed to the API/UI while feeds sync.
type LoadStatus struct {
	Loading    bool   `json:"loading"`
	Error      string `json:"error,omitempty"`
	LastLoaded string `json:"last_loaded,omitempty"`
	FromDisk   bool   `json:"from_disk,omitempty"`
}

func New(enabled bool) *Engine {
	e := &Engine{enabled: enabled}
	e.lastErr.Store("")
	e.lastLoaded.Store(time.Time{})
	return e
}

// SetAxfrState attaches persisted SOA serials for IXFR.
func (e *Engine) SetAxfrState(s *AxfrStateStore) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.axfrState = s
	e.mu.Unlock()
}

// TryBeginLoad marks a reload in progress. Returns false if already loading.
func (e *Engine) TryBeginLoad() bool {
	if e == nil {
		return false
	}
	return e.loading.CompareAndSwap(false, true)
}

func (e *Engine) EndLoad(err error) {
	if e == nil {
		return
	}
	if err != nil {
		e.lastErr.Store(err.Error())
	} else {
		e.lastErr.Store("")
		e.lastLoaded.Store(time.Now().UTC())
	}
	e.loading.Store(false)
}

func (e *Engine) LoadStatus() LoadStatus {
	if e == nil {
		return LoadStatus{}
	}
	st := LoadStatus{Loading: e.loading.Load()}
	if s, ok := e.lastErr.Load().(string); ok {
		st.Error = s
	}
	if t, ok := e.lastLoaded.Load().(time.Time); ok && !t.IsZero() {
		st.LastLoaded = t.Format(time.RFC3339)
	}
	return st
}

func (e *Engine) Enabled() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

func (e *Engine) SetEnabled(on bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.enabled = on
	e.mu.Unlock()
}

// AxfrStatus returns persisted per-feed sync state and recent events for the API/UI.
func (e *Engine) AxfrStatus() (map[string]FeedState, []AxfrEvent) {
	if e == nil {
		return map[string]FeedState{}, nil
	}
	e.mu.RLock()
	state := e.axfrState
	e.mu.RUnlock()
	if state == nil {
		return map[string]FeedState{}, nil
	}
	return state.Snapshot()
}

// PolicyConfig is one feed from TOML / UI.
type PolicyConfig struct {
	Name   string
	Source string // file path or URL (hosts)
	Format string // hosts | axfr
	Action Action
	// Target is required for redirect (IP) and cname (hostname).
	Target string
	// Zone + Masters for format=axfr (slave pull; owner names → RPZ).
	Zone       string
	Masters    []string
	TSIGKey    string // optional TSIG key name
	TSIGSecret string // optional base64 secret resolved from tsig.Store
	// Enabled nil/true = sync; false = skip.
	Enabled *bool
}

// PolicyEnabled reports whether the feed should sync (nil = on).
func PolicyEnabled(p PolicyConfig) bool {
	if p.Enabled == nil {
		return true
	}
	return *p.Enabled
}
