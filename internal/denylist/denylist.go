package denylist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/powersvx/powersvx/internal/config"
)

// List is a manual domain blacklist (NXDOMAIN) checked before RPZ feeds.
// Whitelist still wins when both match.
type List struct {
	mu   sync.RWMutex
	set  map[string]struct{}
	path string
}

type fileShape struct {
	Domains []string `json:"domains"`
}

func New(path string) *List {
	return &List{
		set:  make(map[string]struct{}),
		path: path,
	}
}

func DefaultPath(dataDir string) string {
	return filepath.Join(dataDir, "blacklist.json")
}

func (l *List) Load() error {
	if l == nil || l.path == "" {
		return nil
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var f fileShape
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.set = make(map[string]struct{}, len(f.Domains))
	for _, d := range f.Domains {
		d = normalize(d)
		if d != "" {
			l.set[d] = struct{}{}
		}
	}
	return nil
}

func (l *List) saveLocked() error {
	if l.path == "" {
		return nil
	}
	domains := make([]string, 0, len(l.set))
	for d := range l.set {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	b, err := json.MarshalIndent(fileShape{Domains: domains}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

func normalize(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimSuffix(d, ".")
	if d == "" || d == "*" {
		return ""
	}
	return config.NormalizeName(d)
}

// Blocks reports whether qname (or a parent / wildcard entry) is manually blacklisted.
func (l *List) Blocks(qname string) bool {
	if l == nil {
		return false
	}
	name := normalize(qname)
	if name == "" {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if _, ok := l.set[name]; ok {
		return true
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 1; i < len(labels); i++ {
		parent := strings.Join(labels[i:], ".") + "."
		if _, ok := l.set[parent]; ok {
			return true
		}
		if _, ok := l.set["*."+parent]; ok {
			return true
		}
	}
	if _, ok := l.set["*."+name]; ok {
		return true
	}
	return false
}

func (l *List) Add(domain string) (string, error) {
	d := normalize(domain)
	if d == "" {
		return "", errInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.set[d] = struct{}{}
	return d, l.saveLocked()
}

func (l *List) Remove(domain string) (bool, error) {
	d := normalize(domain)
	if d == "" {
		return false, errInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.set[d]; !ok {
		return false, nil
	}
	delete(l.set, d)
	return true, l.saveLocked()
}

func (l *List) List() []string {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]string, 0, len(l.set))
	for d := range l.set {
		out = append(out, strings.TrimSuffix(d, "."))
	}
	sort.Strings(out)
	return out
}

func (l *List) Count() int {
	if l == nil {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.set)
}

var errInvalid = &domainError{"invalid domain"}

type domainError struct{ s string }

func (e *domainError) Error() string { return e.s }
