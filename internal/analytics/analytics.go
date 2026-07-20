package analytics

import (
	"sort"
	"strings"
	"sync"
)

// Collector keeps bounded aggregate DNS stats (not a live query stream).
type Collector struct {
	mu       sync.Mutex
	rcodes   map[string]uint64
	names    map[string]uint64
	maxNames int
}

func New(maxNames int) *Collector {
	if maxNames <= 0 {
		maxNames = 100
	}
	return &Collector{
		rcodes:   make(map[string]uint64),
		names:    make(map[string]uint64),
		maxNames: maxNames,
	}
}

func (c *Collector) Observe(qname, rcode string) {
	if c == nil {
		return
	}
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	if qname == "" {
		qname = "."
	}
	if rcode == "" {
		rcode = "UNKNOWN"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rcodes[rcode]++
	c.names[qname]++
	if len(c.names) > c.maxNames*2 {
		c.trimLocked()
	}
}

type NameCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type RCodeCount struct {
	RCode string `json:"rcode"`
	Count uint64 `json:"count"`
}

func (c *Collector) Snapshot(topN int) (names []NameCount, rcodes []RCodeCount) {
	if c == nil {
		return nil, nil
	}
	if topN <= 0 {
		topN = 20
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for n, v := range c.names {
		names = append(names, NameCount{Name: n, Count: v})
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i].Count == names[j].Count {
			return names[i].Name < names[j].Name
		}
		return names[i].Count > names[j].Count
	})
	if len(names) > topN {
		names = names[:topN]
	}
	for r, v := range c.rcodes {
		rcodes = append(rcodes, RCodeCount{RCode: r, Count: v})
	}
	sort.Slice(rcodes, func(i, j int) bool {
		if rcodes[i].Count == rcodes[j].Count {
			return rcodes[i].RCode < rcodes[j].RCode
		}
		return rcodes[i].Count > rcodes[j].Count
	})
	return names, rcodes
}

func (c *Collector) trimLocked() {
	type pair struct {
		n string
		c uint64
	}
	all := make([]pair, 0, len(c.names))
	for n, v := range c.names {
		all = append(all, pair{n, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].c > all[j].c })
	c.names = make(map[string]uint64, c.maxNames)
	for i := 0; i < len(all) && i < c.maxNames; i++ {
		c.names[all[i].n] = all[i].c
	}
}
