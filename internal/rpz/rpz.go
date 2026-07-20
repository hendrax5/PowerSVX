package rpz

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/powersvx/powersvx/internal/config"
)

// Action for a matched domain.
type Action string

const (
	ActionNXDOMAIN Action = "nxdomain"
	ActionNODATA   Action = "nodata"
	ActionPass     Action = "pass"
)

// Engine is RPZ / blocklist with label-reversed radix + optional Badger snapshot.
type Engine struct {
	mu         sync.RWMutex
	tree       *trie
	store      *Store
	enabled    bool
	count      atomic.Int64
	hits       atomic.Uint64
	loading    atomic.Bool
	lastErr    atomic.Value // string
	lastLoaded atomic.Value // time.Time
	fromDisk   atomic.Bool
}

// LoadStatus is exposed to the API/UI while feeds sync.
type LoadStatus struct {
	Loading    bool   `json:"loading"`
	Error      string `json:"error,omitempty"`
	LastLoaded string `json:"last_loaded,omitempty"`
	FromDisk   bool   `json:"from_disk,omitempty"`
}

func New(enabled bool) *Engine {
	e := &Engine{
		tree:    newTrie(),
		enabled: enabled,
	}
	e.lastErr.Store("")
	e.lastLoaded.Store(time.Time{})
	return e
}

// OpenDisk attaches Badger at path for restart-safe snapshots.
func (e *Engine) OpenDisk(path string) error {
	if e == nil {
		return nil
	}
	s, err := OpenStore(path)
	if err != nil {
		return err
	}
	e.mu.Lock()
	if e.store != nil {
		_ = e.store.Close()
	}
	e.store = s
	e.mu.Unlock()
	return nil
}

func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.store == nil {
		return nil
	}
	err := e.store.Close()
	e.store = nil
	return err
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
	st := LoadStatus{Loading: e.loading.Load(), FromDisk: e.fromDisk.Load()}
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

func (e *Engine) Count() int64 {
	if e == nil {
		return 0
	}
	return e.count.Load()
}

func (e *Engine) Hits() uint64 {
	if e == nil {
		return 0
	}
	return e.hits.Load()
}

// Lookup returns action and whether domain matched a policy.
func (e *Engine) Lookup(name string) (Action, bool) {
	if !e.Enabled() {
		return ActionPass, false
	}
	e.mu.RLock()
	tree := e.tree
	e.mu.RUnlock()
	if tree == nil {
		return ActionPass, false
	}
	a, ok := tree.lookup(name)
	if ok {
		e.hits.Add(1)
	}
	return a, ok
}

func (e *Engine) replaceTree(t *trie, fromDisk bool) {
	e.mu.Lock()
	e.tree = t
	e.mu.Unlock()
	if t == nil {
		e.count.Store(0)
	} else {
		e.count.Store(int64(t.count))
	}
	e.fromDisk.Store(fromDisk)
}

// Replace installs a map into the radix (tests / small lists).
func (e *Engine) Replace(entries map[string]Action) {
	t := newTrie()
	for k, v := range entries {
		t.insert(k, v)
	}
	e.replaceTree(t, false)
}

func (e *Engine) Add(name string, action Action) {
	if action == "" {
		action = ActionNXDOMAIN
	}
	e.mu.Lock()
	if e.tree == nil {
		e.tree = newTrie()
	}
	before := e.tree.count
	e.tree.insert(name, action)
	after := e.tree.count
	e.mu.Unlock()
	if after > before {
		e.count.Add(1)
	}
}

// TryLoadDisk loads Badger snapshot when fingerprint matches current policies.
func (e *Engine) TryLoadDisk(policies []PolicyConfig) (bool, int, error) {
	if e == nil {
		return false, 0, nil
	}
	e.mu.RLock()
	store := e.store
	e.mu.RUnlock()
	if store == nil {
		return false, 0, nil
	}
	fp := PoliciesFingerprint(policies)
	got, err := store.Fingerprint()
	if err != nil || got != fp {
		return false, 0, nil
	}
	t, n, err := store.LoadTrie()
	if err != nil {
		return false, 0, err
	}
	e.replaceTree(t, true)
	e.lastLoaded.Store(time.Now().UTC())
	e.lastErr.Store("")
	return true, n, nil
}

func (e *Engine) persist(t *trie, policies []PolicyConfig) error {
	e.mu.RLock()
	store := e.store
	e.mu.RUnlock()
	if store == nil || t == nil {
		return nil
	}
	return store.ReplaceAll(t, PoliciesFingerprint(policies))
}

// LoadHostsFile parses hosts-format (0.0.0.0 domain or 127.0.0.1 domain).
func LoadHostsFile(path string, action Action) (map[string]Action, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseHosts(f, action)
}

func LoadHostsURL(url string, action Action, timeout time.Duration) (map[string]Action, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return parseHosts(resp.Body, action)
}

func parseHosts(r io.Reader, action Action) (map[string]Action, error) {
	t := newTrie()
	if err := streamHosts(r, action, t); err != nil {
		return nil, err
	}
	out := make(map[string]Action, t.count)
	t.walk(func(name string, a Action) {
		out[name] = a
	})
	return out, nil
}

func streamHosts(r io.Reader, action Action, t *trie) error {
	if action == "" {
		action = ActionNXDOMAIN
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		var domain string
		switch len(fields) {
		case 1:
			domain = fields[0]
		default:
			domain = fields[1]
		}
		domain = strings.ToLower(domain)
		if domain == "localhost" || domain == "broadcasthost" || strings.HasPrefix(domain, "local") {
			continue
		}
		if !strings.Contains(domain, ".") && domain != "*" {
			continue
		}
		t.insert(config.NormalizeName(domain), action)
	}
	return sc.Err()
}

// PolicyConfig is one feed from TOML / UI.
type PolicyConfig struct {
	Name   string
	Source string // file path or URL
	Format string // hosts
	Action Action
}

// LoadPolicies merges all policies into the radix and snapshots to Badger when configured.
func (e *Engine) LoadPolicies(policies []PolicyConfig, timeout time.Duration) (int, error) {
	merged := newTrie()
	for _, p := range policies {
		action := p.Action
		if action == "" {
			action = ActionNXDOMAIN
		}
		src := p.Source
		var err error
		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
			err = streamHostsURL(src, action, timeout, merged)
		} else {
			err = streamHostsFile(src, action, merged)
		}
		if err != nil {
			return 0, fmt.Errorf("policy %s: %w", p.Name, err)
		}
	}
	e.replaceTree(merged, false)
	_ = e.persist(merged, policies)
	return merged.count, nil
}

func streamHostsFile(path string, action Action, t *trie) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return streamHosts(f, action, t)
}

func streamHostsURL(url string, action Action, timeout time.Duration, t *trie) error {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return streamHosts(resp.Body, action, t)
}
