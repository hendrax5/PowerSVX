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

	"github.com/powersvx/powersvx/internal/bloom"
	"github.com/powersvx/powersvx/internal/config"
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

// Engine is RPZ / blocklist with label-reversed radix + optional Badger snapshot.
type Engine struct {
	mu         sync.RWMutex
	tree       *trie
	bloom      *bloom.Filter
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

// Lookup returns a hit when the domain matched a policy.
func (e *Engine) Lookup(name string) (Hit, bool) {
	if !e.Enabled() {
		return Hit{Action: ActionPass}, false
	}
	e.mu.RLock()
	tree := e.tree
	bf := e.bloom
	e.mu.RUnlock()
	if tree == nil {
		return Hit{Action: ActionPass}, false
	}
	norm := config.NormalizeName(name)
	if bf != nil && !bloomMaybe(bf, norm) {
		return Hit{Action: ActionPass}, false
	}
	h, ok := tree.lookup(name)
	if ok {
		e.hits.Add(1)
	}
	return h, ok
}

func bloomMaybe(bf *bloom.Filter, name string) bool {
	if bf.MightContain(name) {
		return true
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 0; i < len(labels); i++ {
		if bf.MightContain("*." + strings.Join(labels[i:], ".") + ".") {
			return true
		}
	}
	return false
}

func (e *Engine) replaceTree(t *trie, fromDisk bool) {
	var bf *bloom.Filter
	if t != nil && t.count > 0 {
		bf = bloom.New(t.count*2, 0.01)
		t.walk(func(name string, _ Hit) {
			n := config.NormalizeName(name)
			bf.Add(n)
			labels := strings.Split(strings.TrimSuffix(n, "."), ".")
			for i := 1; i < len(labels); i++ {
				bf.Add("*." + strings.Join(labels[i:], ".") + ".")
			}
		})
	}
	e.mu.Lock()
	e.tree = t
	e.bloom = bf
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
	if err := streamHosts(r, Hit{Action: action}, t); err != nil {
		return nil, err
	}
	out := make(map[string]Action, t.count)
	t.walk(func(name string, h Hit) {
		out[name] = h.Action
	})
	return out, nil
}

func streamHosts(r io.Reader, hit Hit, t *trie) error {
	if hit.Action == "" {
		hit.Action = ActionNXDOMAIN
	}
	hit.Target = strings.TrimSpace(hit.Target)
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
		t.insertHit(config.NormalizeName(domain), hit)
	}
	return sc.Err()
}

// PolicyConfig is one feed from TOML / UI.
type PolicyConfig struct {
	Name   string
	Source string // file path or URL
	Format string // hosts
	Action Action
	// Target is required for redirect (IP) and cname (hostname).
	Target string
}

// LoadPolicies merges all policies into the radix and snapshots to Badger when configured.
func (e *Engine) LoadPolicies(policies []PolicyConfig, timeout time.Duration) (int, error) {
	merged := newTrie()
	for _, p := range policies {
		action := p.Action
		if action == "" {
			action = ActionNXDOMAIN
		}
		hit := Hit{Action: action, Target: strings.TrimSpace(p.Target)}
		src := p.Source
		var err error
		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
			err = streamHostsURL(src, hit, timeout, merged)
		} else {
			err = streamHostsFile(src, hit, merged)
		}
		if err != nil {
			return 0, fmt.Errorf("policy %s: %w", p.Name, err)
		}
	}
	e.replaceTree(merged, false)
	_ = e.persist(merged, policies)
	return merged.count, nil
}

func streamHostsFile(path string, hit Hit, t *trie) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return streamHosts(f, hit, t)
}

func streamHostsURL(url string, hit Hit, timeout time.Duration, t *trie) error {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return streamHosts(resp.Body, hit, t)
}
