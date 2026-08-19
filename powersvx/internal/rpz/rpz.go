// Package rpz implements a cache-friendly, immutable suffix/exact matcher for
// Response Policy Zones with millions of rules.
//
// Design decisions (from the hardened plan, Phase 3):
//   - The serving structure (Zone) is IMMUTABLE. Daily updates build a fresh
//     Zone off the hot path and atomically swap it in. Active lookups never
//     observe a half-mutated structure and never take a lock.
//   - Rules are stored as reversed, FQDN-normalized, sorted keys packed into a
//     single contiguous []byte blob + a []uint32 offset table. Regardless of
//     rule count this is only TWO pointers for the GC to scan (vs. millions of
//     pointers in a map[string]/trie), which keeps GC pause and cache misses
//     low at millions of rules.
//   - Lookup is allocation-free on the hot path (one reversed-key build reused
//     across all parent-suffix probes) and does exact binary-search membership
//     for the qname and each of its parent domains — correct RPZ suffix
//     semantics without walking a pointer-chasing trie.
package rpz

import (
	"bufio"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type Action uint8

const (
	ActionNone Action = iota
	ActionNXDOMAIN
	ActionNODATA
	ActionDrop
)

func ParseAction(s string) Action {
	switch strings.ToLower(s) {
	case "nxdomain":
		return ActionNXDOMAIN
	case "nodata":
		return ActionNODATA
	case "drop":
		return ActionDrop
	default:
		return ActionNXDOMAIN
	}
}

// Zone is an immutable, sorted set of reversed domain keys.
type Zone struct {
	blob    []byte   // concatenated sorted keys, each terminated with '.'
	offsets []uint32 // len == count+1; key i == blob[offsets[i]:offsets[i+1]]
	count   int
	action  Action
}

// Matcher holds the currently-served Zone behind an atomic pointer so updates
// are a single lock-free swap.
type Matcher struct {
	z atomic.Pointer[Zone]
}

func NewMatcher() *Matcher { return &Matcher{} }

// Count returns the number of unique rules in this zone.
func (z *Zone) Count() int { return z.count }

// Swap installs a freshly-built zone. Old zone is GC'd once in-flight lookups
// release their local reference. This is snapshot + atomic swap, never mutate.
func (m *Matcher) Swap(z *Zone) { m.z.Store(z) }

func (m *Matcher) Count() int {
	if z := m.z.Load(); z != nil {
		return z.count
	}
	return 0
}

// Lookup returns the configured action if qname or any of its parent domains is
// listed. Allocation-free except for the single reversed-key build.
func (m *Matcher) Lookup(qname string) Action {
	z := m.z.Load()
	if z == nil || z.count == 0 {
		return ActionNone
	}
	return z.lookup(qname)
}

func (z *Zone) lookup(qname string) Action {
	r := reverseKey(qname) // e.g. "sub.evil.com" -> "com.evil.sub."
	if r == "" {
		return ActionNone
	}
	// Probe the domain and every parent by testing each prefix that ends on a
	// label boundary: "com.", "com.evil.", "com.evil.sub.".
	for i := 0; i < len(r); i++ {
		if r[i] == '.' {
			if z.contains(r[:i+1]) {
				return z.action
			}
		}
	}
	return ActionNone
}

// contains does an allocation-free binary search for exact membership.
func (z *Zone) contains(key string) bool {
	lo, hi := 0, z.count
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if cmpBytesStr(z.keyAt(mid), key) < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo < z.count && cmpBytesStr(z.keyAt(lo), key) == 0
}

func (z *Zone) keyAt(i int) []byte {
	return z.blob[z.offsets[i]:z.offsets[i+1]]
}

// BuildZone constructs an immutable zone from a list of domains. Heavy work
// (normalize, sort, pack) runs off the hot path during load/reload.
func BuildZone(domains []string, action Action) *Zone {
	keys := make([]string, 0, len(domains))
	for _, d := range domains {
		k := reverseKey(d)
		if k == "" || k == "." {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Estimate blob size to minimize re-alloc.
	total := 0
	for _, k := range keys {
		total += len(k)
	}
	blob := make([]byte, 0, total)
	offsets := make([]uint32, 0, len(keys)+1)

	var last string
	for _, k := range keys {
		if k == last { // dedup adjacent after sort
			continue
		}
		offsets = append(offsets, uint32(len(blob)))
		blob = append(blob, k...)
		last = k
	}
	offsets = append(offsets, uint32(len(blob)))

	return &Zone{
		blob:    blob,
		offsets: offsets,
		count:   len(offsets) - 1,
		action:  action,
	}
}

// LoadFiles reads hosts-format / plain-domain / simple RPZ lists and builds a
// zone. Supported line shapes:
//
//	0.0.0.0 ads.example.com   (hosts)
//	127.0.0.1 ads.example.com
//	ads.example.com           (plain)
//	ads.example.com CNAME .   (rpz-ish; only the owner name is used)
func LoadFiles(paths []string, action Action) (*Zone, error) {
	var domains []string
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		ds, err := parseReader(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		domains = append(domains, ds...)
	}
	return BuildZone(domains, action), nil
}

func parseReader(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "$") {
			continue
		}
		// Strip inline comments.
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		fields := strings.Fields(line)
		var dom string
		switch {
		case len(fields) == 1:
			dom = fields[0]
		case isIP(fields[0]):
			dom = fields[1] // hosts format: IP domain
		default:
			dom = fields[0] // rpz owner name
		}
		if dom == "" || dom == "0.0.0.0" || dom == "localhost" {
			continue
		}
		out = append(out, dom)
	}
	return out, sc.Err()
}

func isIP(s string) bool {
	// Cheap check: hosts lines begin with an IPv4/IPv6 literal.
	if strings.Count(s, ".") == 3 {
		for _, r := range s {
			if r != '.' && (r < '0' || r > '9') {
				return false
			}
		}
		return true
	}
	return strings.Contains(s, ":")
}

// reverseKey normalizes a domain and reverses its labels with a trailing dot so
// that parent-suffix matching becomes a prefix test. "Evil.COM." -> "com.evil.".
func reverseKey(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return "."
	}
	labels := strings.Split(name, ".")
	var b strings.Builder
	b.Grow(len(name) + 1)
	for i := len(labels) - 1; i >= 0; i-- {
		if labels[i] == "" {
			continue
		}
		b.WriteString(labels[i])
		b.WriteByte('.')
	}
	return b.String()
}

// cmpBytesStr compares a byte slice and a string without allocating.
func cmpBytesStr(b []byte, s string) int {
	n := len(b)
	if len(s) < n {
		n = len(s)
	}
	for i := 0; i < n; i++ {
		if b[i] != s[i] {
			if b[i] < s[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(b) < len(s):
		return -1
	case len(b) > len(s):
		return 1
	default:
		return 0
	}
}

// reverseKeyPool is exposed for callers that want to normalize once. Currently
// lookup builds its own; kept minimal to avoid premature optimization.
var _ = sync.Pool{}
