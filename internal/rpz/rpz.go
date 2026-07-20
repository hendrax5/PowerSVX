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

// Engine is an in-memory RPZ / blocklist (Phase 3 MVP: exact + suffix wildcard).
type Engine struct {
	mu      sync.RWMutex
	exact   map[string]Action // fqdn -> action
	enabled bool
	count   atomic.Int64
	hits    atomic.Uint64
}

func New(enabled bool) *Engine {
	return &Engine{
		exact:   make(map[string]Action),
		enabled: enabled,
	}
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
	name = config.NormalizeName(name)
	e.mu.RLock()
	defer e.mu.RUnlock()

	if a, ok := e.exact[name]; ok {
		e.hits.Add(1)
		return a, true
	}
	// suffix walk: ads.tracker.example.com. → tracker.example.com. → example.com. → com.
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 1; i < len(labels); i++ {
		suf := "*." + strings.Join(labels[i:], ".") + "."
		if a, ok := e.exact[suf]; ok {
			e.hits.Add(1)
			return a, true
		}
	}
	return ActionPass, false
}

func (e *Engine) Replace(entries map[string]Action) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.exact = entries
	e.count.Store(int64(len(entries)))
}

func (e *Engine) Add(name string, action Action) {
	name = config.NormalizeName(name)
	if action == "" {
		action = ActionNXDOMAIN
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.exact[name]; !ok {
		e.count.Add(1)
	}
	e.exact[name] = action
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
	if action == "" {
		action = ActionNXDOMAIN
	}
	out := make(map[string]Action)
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
			// ip domain ...
			domain = fields[1]
		}
		domain = strings.ToLower(domain)
		if domain == "localhost" || domain == "broadcasthost" || strings.HasPrefix(domain, "local") {
			continue
		}
		if !strings.Contains(domain, ".") && domain != "*" {
			continue
		}
		out[config.NormalizeName(domain)] = action
	}
	return out, sc.Err()
}

// PolicyConfig is one feed from TOML.
type PolicyConfig struct {
	Name   string
	Source string // file path or URL
	Format string // hosts
	Action Action
}

// LoadPolicies merges all policies into the engine.
func (e *Engine) LoadPolicies(policies []PolicyConfig, timeout time.Duration) (int, error) {
	merged := make(map[string]Action)
	for _, p := range policies {
		action := p.Action
		if action == "" {
			action = ActionNXDOMAIN
		}
		var (
			m   map[string]Action
			err error
		)
		src := p.Source
		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
			m, err = LoadHostsURL(src, action, timeout)
		} else {
			m, err = LoadHostsFile(src, action)
		}
		if err != nil {
			return 0, fmt.Errorf("policy %s: %w", p.Name, err)
		}
		for k, v := range m {
			merged[k] = v
		}
	}
	e.Replace(merged)
	return len(merged), nil
}
