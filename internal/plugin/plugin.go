package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Decision from a query hook.
type Decision int

const (
	DecisionContinue Decision = iota
	DecisionNXDOMAIN
	DecisionNODATA
	DecisionRefused
)

// QueryCtx is the minimal query context passed to plugins.
type QueryCtx struct {
	Name     string
	Qtype    uint16
	ClientIP string
}

// Hook filters DNS queries before RPZ/cache.
type Hook interface {
	Name() string
	OnQuery(q QueryCtx) Decision
}

// Registry holds ordered hooks (Lua then WASM).
type Registry struct {
	mu    sync.RWMutex
	hooks []Hook
}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.hooks)
}

func (r *Registry) Add(h Hook) {
	if r == nil || h == nil {
		return
	}
	r.mu.Lock()
	r.hooks = append(r.hooks, h)
	r.mu.Unlock()
}

// Decide runs hooks in order; first non-Continue wins.
func (r *Registry) Decide(q QueryCtx) (Decision, string) {
	if r == nil {
		return DecisionContinue, ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, h := range r.hooks {
		if d := h.OnQuery(q); d != DecisionContinue {
			return d, h.Name()
		}
	}
	return DecisionContinue, ""
}

// LoadDir loads *.lua and *.wasm from dir (non-recursive). Missing dir is OK.
func LoadDir(dir string) (*Registry, error) {
	reg := NewRegistry()
	if dir == "" {
		return reg, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return reg, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".lua":
			h, err := LoadLua(path)
			if err != nil {
				return nil, fmt.Errorf("lua %s: %w", e.Name(), err)
			}
			reg.Add(h)
		case ".wasm":
			h, err := LoadWASM(path)
			if err != nil {
				return nil, fmt.Errorf("wasm %s: %w", e.Name(), err)
			}
			reg.Add(h)
		}
	}
	return reg, nil
}

// Reload replaces hooks from dir (hot-reload). On error, previous hooks are kept.
func (r *Registry) Reload(dir string) error {
	if r == nil {
		return fmt.Errorf("nil registry")
	}
	fresh, err := LoadDir(dir)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.hooks = fresh.hooks
	r.mu.Unlock()
	return nil
}

// ApplyDecision writes a DNS response for a blocking decision.
func ApplyDecision(w dns.ResponseWriter, req *dns.Msg, d Decision) bool {
	if d == DecisionContinue {
		return false
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	switch d {
	case DecisionNODATA:
		m.Rcode = dns.RcodeSuccess
	case DecisionRefused:
		m.Rcode = dns.RcodeRefused
	default:
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
	return true
}
