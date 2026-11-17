package rpz

import (
	"bufio"
	"context"
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

// Engine is RPZ / blocklist with optional cold tier (Bloom + Badger + hot cache).
// When a disk store is attached, exact domains stay on disk; only Bloom, wildcards,
// and a hot LRU stay in RAM (~tens–hundreds of MB for multi‑million feeds).
type Engine struct {
	mu         sync.RWMutex
	tree       *trie // full in-RAM trie when store is nil (tests / tiny lists)
	wild       *trie // wildcard-only trie in cold mode
	bloom      *bloom.Filter
	hot        *hotCache
	neg        *negCache
	hotMax     int
	cold       bool // exact names served from Badger
	store      *Store
	enabled    bool
	count      atomic.Int64
	hits       atomic.Uint64
	loading    atomic.Bool
	lastErr    atomic.Value // string
	lastLoaded atomic.Value // time.Time
	fromDisk   atomic.Bool
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
	e := &Engine{
		tree:    newTrie(),
		enabled: enabled,
		hotMax:  500_000,
	}
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

// SetHotCacheSize sets max exact hits retained in RAM (cold mode). 0 = default 500k.
func (e *Engine) SetHotCacheSize(n int) {
	if e == nil {
		return
	}
	if n <= 0 {
		n = 500_000
	}
	e.mu.Lock()
	e.hotMax = n
	e.mu.Unlock()
}

// reloadColdIndex rebuilds Bloom/wild from Badger after incremental AXFR/IXFR.
func (e *Engine) reloadColdIndex() (int, error) {
	e.mu.RLock()
	store := e.store
	hotMax := e.hotMax
	e.mu.RUnlock()
	if store == nil {
		return 0, fmt.Errorf("no disk store")
	}
	bf, wild, n, err := store.BuildColdIndex()
	if err != nil {
		return 0, err
	}
	if hotMax <= 0 {
		hotMax = 500_000
	}
	e.mu.Lock()
	e.tree = nil
	e.wild = wild
	e.bloom = bf
	e.cold = true
	e.hot = newHot(hotMax)
	e.neg = newNeg(hotMax, 30*time.Second)
	e.mu.Unlock()
	e.count.Store(int64(n))
	e.fromDisk.Store(false)
	return n, nil
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

// SeedHot preloads the RAM hot cache for known-blocked names (cold/disk mode).
// Skips names not present in the store/trie. Does not increment hit counters.
func (e *Engine) SeedHot(names []string) int {
	if e == nil || len(names) == 0 || !e.Enabled() {
		return 0
	}
	e.mu.RLock()
	cold := e.cold
	store := e.store
	hot := e.hot
	tree := e.tree
	wild := e.wild
	e.mu.RUnlock()
	if hot == nil {
		return 0
	}
	seeded := 0
	for _, name := range names {
		norm := config.NormalizeName(name)
		if norm == "" || norm == "." {
			continue
		}
		var hit Hit
		var ok bool
		if cold && store != nil {
			hit, ok, _ = store.Get(norm)
			if !ok && wild != nil {
				hit, ok = wild.lookup(norm)
			}
		} else if tree != nil {
			hit, ok = tree.lookup(norm)
		}
		if !ok || hit.Action == ActionPass {
			continue
		}
		hot.Set(norm, hit)
		seeded++
	}
	return seeded
}

// Lookup returns a hit when the domain matched a policy.
func (e *Engine) Lookup(name string) (Hit, bool) {
	if !e.Enabled() {
		return Hit{Action: ActionPass}, false
	}
	e.mu.RLock()
	cold := e.cold
	tree := e.tree
	wild := e.wild
	bf := e.bloom
	store := e.store
	hot := e.hot
	neg := e.neg
	e.mu.RUnlock()

	norm := config.NormalizeName(name)

	if cold {
		if hot != nil {
			if h, ok := hot.Get(norm); ok {
				e.hits.Add(1)
				return h, true
			}
		}
		// Skip Badger when a recent bloom false-positive was recorded.
		if neg == nil || !neg.Has(norm) {
			if bf == nil || bf.MightContain(norm) {
				if store != nil {
					if h, ok, err := store.Get(norm); err == nil && ok {
						if hot != nil {
							hot.Set(norm, h)
						}
						e.hits.Add(1)
						return h, true
					}
					// Bloom said maybe but disk miss → remember to avoid repeat I/O.
					if bf != nil && neg != nil && bf.MightContain(norm) {
						neg.Set(norm)
					}
				}
			}
		}
		if wild != nil {
			if h, ok := wild.lookup(name); ok {
				e.hits.Add(1)
				return h, true
			}
		}
		return Hit{Action: ActionPass}, false
	}

	if tree == nil {
		return Hit{Action: ActionPass}, false
	}
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

func splitCold(t *trie) (bf *bloom.Filter, wild *trie) {
	n := t.count
	if n < 1 {
		n = 1
	}
	bf = bloom.New(n*2, 0.001)
	wild = newTrie()
	t.walk(func(name string, hit Hit) {
		norm := config.NormalizeName(name)
		bf.Add(norm)
		if strings.HasPrefix(norm, "*.") {
			wild.insertHit(norm, hit)
		}
	})
	return bf, wild
}

func (e *Engine) replaceTree(t *trie, fromDisk bool) {
	e.mu.RLock()
	store := e.store
	e.mu.RUnlock()
	if store != nil && t != nil && t.count > 0 {
		e.replaceTreeCold(t, fromDisk)
		return
	}
	e.replaceTreeRAM(t, fromDisk)
}

func (e *Engine) replaceTreeCold(t *trie, fromDisk bool) {
	hotMax := e.hotMax
	if hotMax <= 0 {
		hotMax = 500_000
	}
	bf, wild := splitCold(t)
	e.mu.Lock()
	e.tree = nil
	e.wild = wild
	e.bloom = bf
	e.cold = true
	e.hot = newHot(hotMax)
	e.neg = newNeg(hotMax, 30*time.Second)
	e.mu.Unlock()
	e.count.Store(int64(t.count))
	e.fromDisk.Store(fromDisk)
}

func (e *Engine) replaceTreeRAM(t *trie, fromDisk bool) {
	var bf *bloom.Filter
	if t != nil && t.count > 0 {
		bf = bloom.New(t.count*2, 0.001)
		t.walk(func(name string, _ Hit) {
			bf.Add(config.NormalizeName(name))
		})
	}
	e.mu.Lock()
	e.tree = t
	e.wild = nil
	e.bloom = bf
	e.cold = false
	e.hot = nil
	e.neg = nil
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
	hit := Hit{Action: action}
	norm := config.NormalizeName(name)

	e.mu.Lock()
	store := e.store
	cold := e.cold
	if cold && store != nil {
		bf := e.bloom
		wild := e.wild
		hot := e.hot
		e.mu.Unlock()
		_ = store.Put(norm, hit)
		e.mu.Lock()
		if bf != nil {
			bf.Add(norm)
		}
		if strings.HasPrefix(norm, "*.") {
			if wild == nil {
				wild = newTrie()
				e.wild = wild
			}
			before := wild.count
			wild.insertHit(norm, hit)
			if wild.count > before {
				e.count.Add(1)
			}
		} else {
			e.count.Add(1)
			if hot != nil {
				hot.Set(norm, hit)
			}
		}
		e.mu.Unlock()
		return
	}
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
// Uses cold index (Bloom + wild trie) — does not rehydrate millions of exact domains into RAM.
func (e *Engine) TryLoadDisk(policies []PolicyConfig) (bool, int, error) {
	if e == nil {
		return false, 0, nil
	}
	e.mu.RLock()
	store := e.store
	hotMax := e.hotMax
	e.mu.RUnlock()
	if store == nil {
		return false, 0, nil
	}
	fp := PoliciesFingerprint(policies)
	got, err := store.Fingerprint()
	if err != nil || got != fp {
		return false, 0, nil
	}
	bf, wild, n, err := store.BuildColdIndex()
	if err != nil {
		return false, 0, err
	}
	if hotMax <= 0 {
		hotMax = 500_000
	}
	e.mu.Lock()
	e.tree = nil
	e.wild = wild
	e.bloom = bf
	e.cold = true
	e.hot = newHot(hotMax)
	e.neg = newNeg(hotMax, 30*time.Second)
	e.mu.Unlock()
	e.count.Store(int64(n))
	e.fromDisk.Store(true)
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

// domainSink receives streamed RPZ domains (RAM trie or Badger ReplaceBuilder).
type domainSink interface {
	Put(name string, hit Hit) error
}

type feedSink struct {
	b      *ReplaceBuilder
	policy string
}

func (f feedSink) Put(name string, hit Hit) error {
	return f.b.PutFeed(f.policy, name, hit)
}

func streamHosts(r io.Reader, hit Hit, sink domainSink) error {
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
		if err := sink.Put(config.NormalizeName(domain), hit); err != nil {
			return err
		}
	}
	return sc.Err()
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

func (p PolicyConfig) tsigAuth() TSIGAuth {
	if p.TSIGKey == "" || p.TSIGSecret == "" {
		return TSIGAuth{}
	}
	return TSIGAuth{Name: p.TSIGKey, Secret: p.TSIGSecret}
}

// PolicyEnabled reports whether the feed should sync (nil = on).
func PolicyEnabled(p PolicyConfig) bool {
	if p.Enabled == nil {
		return true
	}
	return *p.Enabled
}

func (e *Engine) applyColdIndex(bf *bloom.Filter, wild *trie, n int, fromDisk bool) {
	hotMax := e.hotMax
	if hotMax <= 0 {
		hotMax = 500_000
	}
	e.mu.Lock()
	e.tree = nil
	e.wild = wild
	e.bloom = bf
	e.cold = true
	e.hot = newHot(hotMax)
	e.neg = newNeg(hotMax, 30*time.Second)
	e.mu.Unlock()
	e.count.Store(int64(n))
	e.fromDisk.Store(fromDisk)
	e.lastLoaded.Store(time.Now().UTC())
	e.lastErr.Store("")
}

// LoadPolicies merges all policies into the radix and snapshots to Badger when configured.
// With a disk store, domains stream into Badger (no multi-million-node RAM trie) to avoid OOM.
func (e *Engine) LoadPolicies(policies []PolicyConfig, timeout time.Duration) (int, error) {
	if timeout <= 0 {
		timeout = defaultAXFRTimeout
	}
	e.mu.RLock()
	store := e.store
	state := e.axfrState
	e.mu.RUnlock()
	if store != nil {
		return e.loadPoliciesDisk(policies, timeout, store, state)
	}
	return e.loadPoliciesRAM(policies, timeout, state)
}

func (e *Engine) loadPoliciesDisk(policies []PolicyConfig, timeout time.Duration, store *Store, state *AxfrStateStore) (int, error) {
	// Open/download hosts feeds before BeginReplace — Replace wipes the Badger directory.
	type hostsFeed struct {
		name    string
		hit     Hit
		path    string
		cleanup bool
	}
	var hosts []hostsFeed
	var axfrPols []PolicyConfig
	axfrSerials := map[string]struct {
		zone   string
		serial uint32
	}{}
	keepFeeds := map[string]bool{}

	for _, p := range policies {
		if !PolicyEnabled(p) {
			continue
		}
		action := p.Action
		if action == "" {
			action = ActionNXDOMAIN
		}
		hit := Hit{Action: action, Target: strings.TrimSpace(p.Target)}
		format := strings.ToLower(strings.TrimSpace(p.Format))
		if format == "" {
			format = "hosts"
		}
		switch format {
		case "axfr":
			keepFeeds[p.Name] = true
			axfrPols = append(axfrPols, p)
		case "hosts":
			src := p.Source
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
				tmp, err := downloadHostsTemp(src, timeout)
				if err != nil {
					return 0, fmt.Errorf("policy %s: %w", p.Name, err)
				}
				hosts = append(hosts, hostsFeed{name: p.Name, hit: hit, path: tmp, cleanup: true})
			} else {
				if _, err := os.Stat(src); err != nil {
					return 0, fmt.Errorf("policy %s: %w", p.Name, err)
				}
				hosts = append(hosts, hostsFeed{name: p.Name, hit: hit, path: src})
			}
		default:
			return 0, fmt.Errorf("policy %s: unsupported format %q", p.Name, p.Format)
		}
	}
	defer func() {
		for _, h := range hosts {
			if h.cleanup {
				_ = os.Remove(h.path)
			}
		}
	}()

	b, err := store.BeginReplace(10_000_000)
	if err != nil {
		return 0, fmt.Errorf("rpz begin replace: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			b.Cancel()
		}
	}()

	for _, h := range hosts {
		if err := streamHostsFile(h.path, h.hit, b); err != nil {
			return 0, fmt.Errorf("policy %s: %w", h.name, err)
		}
	}
	for _, p := range axfrPols {
		action := p.Action
		if action == "" {
			action = ActionNXDOMAIN
		}
		hit := Hit{Action: action, Target: strings.TrimSpace(p.Target)}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		serial, _, err := streamAXFRToSinkWithTSIG(ctx, p.Zone, p.Masters, hit, feedSink{b: b, policy: p.Name}, p.tsigAuth())
		cancel()
		if err != nil {
			return 0, fmt.Errorf("policy %s: %w", p.Name, err)
		}
		axfrSerials[p.Name] = struct {
			zone   string
			serial uint32
		}{zone: config.NormalizeName(p.Zone), serial: serial}
	}

	bf, wild, n, err := b.Finish(PoliciesFingerprint(policies))
	if err != nil {
		return 0, fmt.Errorf("rpz finish replace: %w", err)
	}
	ok = true
	e.applyColdIndex(bf, wild, n, true)
	if state != nil {
		_ = state.Prune(keepFeeds)
		for name, meta := range axfrSerials {
			_ = state.Set(name, meta.zone, meta.serial)
		}
	}
	return n, nil
}

func downloadHostsTemp(url string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.CreateTemp("", "powersvx-hosts-*.txt")
	if err != nil {
		return "", err
	}
	path := f.Name()
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(path)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return "", closeErr
	}
	return path, nil
}

func (e *Engine) loadPoliciesRAM(policies []PolicyConfig, timeout time.Duration, state *AxfrStateStore) (int, error) {
	merged := newTrie()
	axfrSerials := map[string]struct {
		zone   string
		serial uint32
	}{}
	keepFeeds := map[string]bool{}
	for _, p := range policies {
		if !PolicyEnabled(p) {
			continue
		}
		action := p.Action
		if action == "" {
			action = ActionNXDOMAIN
		}
		hit := Hit{Action: action, Target: strings.TrimSpace(p.Target)}
		format := strings.ToLower(strings.TrimSpace(p.Format))
		if format == "" {
			format = "hosts"
		}
		var err error
		switch format {
		case "axfr":
			keepFeeds[p.Name] = true
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			var serial uint32
			serial, _, err = streamAXFRToSinkWithTSIG(ctx, p.Zone, p.Masters, hit, merged, p.tsigAuth())
			cancel()
			if err == nil {
				axfrSerials[p.Name] = struct {
					zone   string
					serial uint32
				}{zone: config.NormalizeName(p.Zone), serial: serial}
			}
		case "hosts":
			src := p.Source
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
				err = streamHostsURL(src, hit, timeout, merged)
			} else {
				err = streamHostsFile(src, hit, merged)
			}
		default:
			err = fmt.Errorf("unsupported format %q", p.Format)
		}
		if err != nil {
			return 0, fmt.Errorf("policy %s: %w", p.Name, err)
		}
	}
	e.replaceTreeRAM(merged, false)
	e.lastLoaded.Store(time.Now().UTC())
	e.lastErr.Store("")
	if state != nil {
		_ = state.Prune(keepFeeds)
		for name, meta := range axfrSerials {
			_ = state.Set(name, meta.zone, meta.serial)
		}
	}
	return merged.count, nil
}

// RefreshAXFR updates only format=axfr feeds via SOA check + IXFR (fallback AXFR).
// Hosts feeds are left untouched (no HTTP re-download).
func (e *Engine) RefreshAXFR(policies []PolicyConfig, timeout time.Duration) (int, error) {
	if e == nil {
		return 0, nil
	}
	if timeout <= 0 {
		timeout = defaultAXFRTimeout
	}
	e.mu.RLock()
	store := e.store
	state := e.axfrState
	e.mu.RUnlock()

	keepFeeds := map[string]bool{}
	var axfrPols []PolicyConfig
	for _, p := range policies {
		if !strings.EqualFold(strings.TrimSpace(p.Format), "axfr") {
			continue
		}
		if !PolicyEnabled(p) {
			continue
		}
		axfrPols = append(axfrPols, p)
		keepFeeds[p.Name] = true
	}
	if state != nil {
		_ = state.Prune(keepFeeds)
	}
	if len(axfrPols) == 0 {
		if store != nil {
			return e.reloadColdIndex()
		}
		return int(e.count.Load()), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	changed := false
	for _, p := range axfrPols {
		action := p.Action
		if action == "" {
			action = ActionNXDOMAIN
		}
		hit := Hit{Action: action, Target: strings.TrimSpace(p.Target)}
		zone := config.NormalizeName(p.Zone)

		auth := p.tsigAuth()
		remoteSerial, master, err := QuerySOASerialWithTSIG(ctx, zone, p.Masters, auth)
		if err != nil {
			if state != nil {
				_ = state.PutFailure(p.Name, zone, "", fmt.Sprintf("SOA failed: %v", err))
			}
			return 0, fmt.Errorf("policy %s soa: %w", p.Name, err)
		}
		var localSerial uint32
		if state != nil {
			if st, ok := state.Get(p.Name); ok && config.NormalizeName(st.Zone) == zone {
				localSerial = st.Serial
			}
		}
		if localSerial != 0 && !SerialGreater(remoteSerial, localSerial) {
			if state != nil {
				_ = state.PutSuccess(p.Name, zone, "skipped", master, remoteSerial,
					fmt.Sprintf("SOA unchanged · serial %d · master %s", remoteSerial, master))
			}
			continue
		}

		res, err := PullZoneWithTSIG(ctx, zone, p.Masters, localSerial, auth)
		if err != nil {
			if state != nil {
				_ = state.PutFailure(p.Name, zone, master, fmt.Sprintf("transfer failed: %v", err))
			}
			return 0, fmt.Errorf("policy %s transfer: %w", p.Name, err)
		}
		if res.Master != "" {
			master = res.Master
		}
		mode := "ixfr"
		if res.FullReplace || localSerial == 0 {
			mode = "full_axfr"
		}
		if !res.FullReplace && localSerial != 0 && len(res.Added) == 0 && len(res.Removed) == 0 {
			if state != nil {
				_ = state.PutSuccess(p.Name, zone, "skipped", master, res.Serial,
					fmt.Sprintf("IXFR empty · serial %d", res.Serial))
			}
			continue
		}

		if store != nil {
			if res.FullReplace || localSerial == 0 {
				if err := store.ReplaceFeed(p.Name, res.Names, hit); err != nil {
					if state != nil {
						_ = state.PutFailure(p.Name, zone, master, fmt.Sprintf("replace failed: %v", err))
					}
					return 0, fmt.Errorf("policy %s replace: %w", p.Name, err)
				}
			} else {
				if err := store.ApplyFeedDelta(p.Name, res.Added, res.Removed, hit); err != nil {
					if state != nil {
						_ = state.PutFailure(p.Name, zone, master, fmt.Sprintf("IXFR apply failed: %v", err))
					}
					return 0, fmt.Errorf("policy %s ixfr apply: %w", p.Name, err)
				}
			}
			changed = true
		} else {
			e.mu.Lock()
			if e.tree == nil {
				e.tree = newTrie()
			}
			if res.FullReplace || localSerial == 0 {
				for _, n := range res.Names {
					e.tree.insertHit(n, hit)
				}
			} else {
				for _, n := range res.Added {
					e.tree.insertHit(n, hit)
				}
			}
			e.count.Store(int64(e.tree.count))
			e.mu.Unlock()
			changed = true
		}
		if state != nil {
			msg := fmt.Sprintf("%s ok · serial %d", strings.ToUpper(mode), res.Serial)
			if mode == "ixfr" {
				msg = fmt.Sprintf("IXFR ok · +%d −%d · serial %d · master %s",
					len(res.Added), len(res.Removed), res.Serial, master)
			} else {
				msg = fmt.Sprintf("AXFR ok · %d names · serial %d · master %s",
					len(res.Names), res.Serial, master)
			}
			_ = state.PutSuccess(p.Name, zone, mode, master, res.Serial, msg)
		}
	}

	if store != nil {
		_ = store.SetFingerprint(PoliciesFingerprint(policies))
		n, err := e.reloadColdIndex()
		if err != nil {
			return 0, err
		}
		if changed {
			e.lastLoaded.Store(time.Now().UTC())
		}
		return n, nil
	}
	return int(e.count.Load()), nil
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

func streamHostsFile(path string, hit Hit, sink domainSink) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return streamHosts(f, hit, sink)
}

func streamHostsURL(url string, hit Hit, timeout time.Duration, sink domainSink) error {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return streamHosts(resp.Body, hit, sink)
}
