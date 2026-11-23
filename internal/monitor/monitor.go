package monitor

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	qpsWindowSec   = 900 // 15 minutes
	latencySamples = 2048
	maxClients     = 200
	maxRLOffenders = 100
)

// Sample is one finished DNS query observation.
type Sample struct {
	ClientIP    string
	QName       string
	Latency     time.Duration
	Path        string // cache, auth, recursive, forward, fallback, acl_denied, ratelimited, rpz, ...
	RCode       string
	ACLDenied   bool
	RateLimited bool
	Timeout     bool
}

// Collector aggregates live monitoring stats for the dashboard.
type Collector struct {
	mu sync.Mutex

	// qpsRing[i] = query count for unix second (qpsEpoch + i)
	qpsRing  [qpsWindowSec]uint64
	qpsEpoch int64

	clients  map[string]uint64
	subnets  map[string]uint64
	paths    map[string]uint64
	errors   map[string]uint64
	blocked  map[string]uint64 // qname -> count (RPZ blocks)
	aclAllow uint64
	aclDeny  uint64
	queries  uint64
	rlHits   map[string]uint64
	rlTotal  uint64

	recent []RecentQuery
	recI   int
	recN   int

	latRing [latencySamples]float64 // milliseconds
	latN    int
	latI    int

	fwdOK   map[string]uint64
	fwdFail map[string]uint64
	fwdLast map[string]string
	fwdMS   map[string]int64
}

const (
	maxBlockedNames = 5000 // retain enough names for hot-seed + cover analysis
	recentCap       = 50
)

// default cover thresholds for dashboard "how many top names catch X% of blocks"
var defaultCoverNs = []int{1000, 5000, 20000, 50000}

// CoverStat is cumulative block-hit coverage if only the top-N blocked names are kept.
type CoverStat struct {
	N       int     `json:"n"`
	Names   int     `json:"names"` // min(n, tracked)
	Hits    uint64  `json:"hits"`
	Percent float64 `json:"percent"`
}

// RecentQuery is a short live query for the dashboard (Pi-hole style).
type RecentQuery struct {
	Time     time.Time `json:"time"`
	ClientIP string    `json:"client_ip"`
	QName    string    `json:"qname"`
	Path     string    `json:"path"`
	RCode    string    `json:"rcode"`
	Blocked  bool      `json:"blocked"`
	MS       float64   `json:"ms"`
}

func New() *Collector {
	now := time.Now().Unix()
	return &Collector{
		clients:  make(map[string]uint64),
		subnets:  make(map[string]uint64),
		paths:    make(map[string]uint64),
		errors:   make(map[string]uint64),
		blocked:  make(map[string]uint64),
		rlHits:   make(map[string]uint64),
		fwdOK:    make(map[string]uint64),
		fwdFail:  make(map[string]uint64),
		fwdLast:  make(map[string]string),
		fwdMS:    make(map[string]int64),
		recent:   make([]RecentQuery, recentCap),
		qpsEpoch: now - qpsWindowSec + 1,
	}
}

func (c *Collector) Observe(s Sample) {
	if c == nil {
		return
	}
	now := time.Now().Unix()
	ms := s.Latency.Seconds() * 1000
	if ms < 0 {
		ms = 0
	}
	path := s.Path
	if path == "" {
		path = "unknown"
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.advanceQPSLocked(now)
	idx := int(now - c.qpsEpoch)
	if idx >= 0 && idx < qpsWindowSec {
		c.qpsRing[idx]++
	}

	c.paths[path]++
	c.queries++

	if s.ACLDenied || path == "acl_denied" {
		c.aclDeny++
	} else {
		c.aclAllow++
	}

	isBlocked := path == "rpz"
	if isBlocked {
		qname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.QName), "."))
		if qname == "" {
			qname = "."
		}
		c.blocked[qname]++
		if len(c.blocked) > maxBlockedNames*2 {
			trimMap(c.blocked, maxBlockedNames)
		}
	}

	if s.RateLimited || path == "ratelimited" {
		c.rlTotal++
		if ip := strings.TrimSpace(s.ClientIP); ip != "" {
			c.rlHits[ip]++
			if len(c.rlHits) > maxRLOffenders*2 {
				trimMap(c.rlHits, maxRLOffenders)
			}
		}
	}

	if ip := strings.TrimSpace(s.ClientIP); ip != "" && !(s.ACLDenied || path == "acl_denied") {
		c.clients[ip]++
		if sub := subnetOf(ip); sub != "" {
			c.subnets[sub]++
		}
		if len(c.clients) > maxClients*2 {
			trimMap(c.clients, maxClients)
		}
		if len(c.subnets) > maxClients*2 {
			trimMap(c.subnets, maxClients)
		}
	}

	c.latRing[c.latI] = ms
	c.latI = (c.latI + 1) % latencySamples
	if c.latN < latencySamples {
		c.latN++
	}

	if kind := errorKind(s); kind != "" {
		c.errors[kind]++
	}

	c.recent[c.recI] = RecentQuery{
		Time:     time.Now().UTC(),
		ClientIP: strings.TrimSpace(s.ClientIP),
		QName:    strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.QName), ".")),
		Path:     path,
		RCode:    s.RCode,
		Blocked:  isBlocked,
		MS:       ms,
	}
	c.recI = (c.recI + 1) % recentCap
	if c.recN < recentCap {
		c.recN++
	}
}

// RecordBulk adds n queries to the current second (external dataplane sampler).
// path is recorded once per query (e.g. "unbound_cache", "unbound_recurse", "rpz").
func (c *Collector) RecordBulk(path string, n uint64) {
	if c == nil || n == 0 {
		return
	}
	if path == "" {
		path = "unbound"
	}
	now := time.Now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advanceQPSLocked(now)
	idx := int(now - c.qpsEpoch)
	if idx >= 0 && idx < qpsWindowSec {
		c.qpsRing[idx] += n
	}
	c.paths[path] += n
	c.queries += n
	c.aclAllow += n
}

// RecordPathOnly increments a path counter without adding QPS/queries (e.g. RPZ actions
// that are already included in Unbound total.num.queries).
func (c *Collector) RecordPathOnly(path string, n uint64) {
	if c == nil || n == 0 || path == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paths[path] += n
}

// RecordForwarder tracks upstream forwarder health.
func (c *Collector) RecordForwarder(addr string, ok bool, latencyMS int64, errMsg string) {
	if c == nil || addr == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ok {
		c.fwdOK[addr]++
		c.fwdLast[addr] = "ok"
	} else {
		c.fwdFail[addr]++
		if errMsg == "" {
			errMsg = "error"
		}
		c.fwdLast[addr] = errMsg
	}
	c.fwdMS[addr] = latencyMS
}

type Point struct {
	T   int64   `json:"t"`
	QPS float64 `json:"qps"`
}

type Count struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
}

type ForwarderHealth struct {
	Addr       string `json:"addr"`
	OK         uint64 `json:"ok"`
	Fail       uint64 `json:"fail"`
	LastMS     int64  `json:"last_ms"`
	LastStatus string `json:"last_status"`
}

type Latency struct {
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	P99 float64 `json:"p99_ms"`
	N   int     `json:"samples"`
}

type Resources struct {
	Goroutines int     `json:"goroutines"`
	AllocMB    float64 `json:"alloc_mb"`
	SysMB      float64 `json:"sys_mb"`
	HeapMB     float64 `json:"heap_mb"`
	NumGC      uint32  `json:"num_gc"`
	CPUPercent float64 `json:"cpu_percent"`
	RSSMB      float64 `json:"rss_mb"`
	NumCPU     int     `json:"num_cpu"`
	// Host-wide (dataplane machine), not just the Go process.
	HostMemTotalMB     float64 `json:"host_mem_total_mb,omitempty"`
	HostMemAvailableMB float64 `json:"host_mem_available_mb,omitempty"`
	HostMemUsedPct     float64 `json:"host_mem_used_pct,omitempty"`
	DiskTotalGB        float64 `json:"disk_total_gb,omitempty"`
	DiskUsedGB         float64 `json:"disk_used_gb,omitempty"`
	DiskUsedPct        float64 `json:"disk_used_pct,omitempty"`
	Load1              float64 `json:"load1,omitempty"`
}

type Snapshot struct {
	QPSNow           float64           `json:"qps_now"`
	QPSSeries        []Point           `json:"qps_series"`
	TopClients       []Count           `json:"top_clients"`
	TopSubnets       []Count           `json:"top_subnets"`
	TopBlocked       []Count           `json:"top_blocked"`
	BlockedCover     []CoverStat       `json:"blocked_cover"`
	Latency          Latency           `json:"latency"`
	Paths            []Count           `json:"paths"`
	Errors           []Count           `json:"errors"`
	QueriesTotal     uint64            `json:"queries_total"`
	BlockedTotal     uint64            `json:"blocked_total"`
	BlockedPercent   float64           `json:"blocked_percent"`
	ACLAllow         uint64            `json:"acl_allow"`
	ACLDeny          uint64            `json:"acl_deny"`
	ACLOpenResolver  bool              `json:"acl_open_resolver"`
	RateLimitedTotal uint64            `json:"rate_limited_total"`
	RateLimitTop     []Count           `json:"rate_limit_top"`
	RateLimitActive  []Count           `json:"rate_limit_active"`
	Forwarders       []ForwarderHealth `json:"forwarders"`
	Recent           []RecentQuery     `json:"recent"`
	Resources        Resources         `json:"resources"`
}

func (c *Collector) Snapshot(allowCIDRs []string, activeBlocked []Count) Snapshot {
	out := Snapshot{
		QPSSeries:       []Point{},
		TopClients:      []Count{},
		TopSubnets:      []Count{},
		TopBlocked:      []Count{},
		BlockedCover:    []CoverStat{},
		Paths:           []Count{},
		Errors:          []Count{},
		RateLimitTop:    []Count{},
		RateLimitActive: activeBlocked,
		Forwarders:      []ForwarderHealth{},
		Recent:          []RecentQuery{},
		Resources:       resourceSnapshot(),
		ACLOpenResolver: len(allowCIDRs) == 0,
	}
	if activeBlocked == nil {
		out.RateLimitActive = []Count{}
	}
	if c == nil {
		return out
	}

	now := time.Now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advanceQPSLocked(now)

	if idx := int(now - c.qpsEpoch); idx > 0 && idx < qpsWindowSec {
		out.QPSNow = float64(c.qpsRing[idx-1])
	} else if idx == 0 {
		out.QPSNow = float64(c.qpsRing[0])
	}

	const step = 10
	start := now - qpsWindowSec + step
	for t := start; t <= now; t += step {
		var sum uint64
		for i := 0; i < step; i++ {
			sec := t - int64(step-1-i)
			idx := int(sec - c.qpsEpoch)
			if idx >= 0 && idx < qpsWindowSec {
				sum += c.qpsRing[idx]
			}
		}
		out.QPSSeries = append(out.QPSSeries, Point{T: t, QPS: float64(sum) / float64(step)})
	}

	out.TopClients = topN(c.clients, 15)
	out.TopSubnets = topN(c.subnets, 15)
	out.TopBlocked = topN(c.blocked, 50)
	out.BlockedCover = blockedCoverLocked(c.blocked, defaultCoverNs)
	out.Paths = topN(c.paths, 20)
	out.Errors = topN(c.errors, 20)
	out.ACLAllow = c.aclAllow
	out.ACLDeny = c.aclDeny
	out.RateLimitedTotal = c.rlTotal
	out.RateLimitTop = topN(c.rlHits, 10)
	out.Latency = percentileLocked(c)
	out.Forwarders = forwarderListLocked(c)
	out.QueriesTotal = c.queries
	out.BlockedTotal = c.paths["rpz"]
	if c.queries > 0 {
		out.BlockedPercent = 100 * float64(out.BlockedTotal) / float64(c.queries)
	}
	out.Recent = recentLocked(c)
	return out
}

func recentLocked(c *Collector) []RecentQuery {
	n := c.recN
	if n == 0 {
		return []RecentQuery{}
	}
	out := make([]RecentQuery, 0, n)
	for i := 0; i < n; i++ {
		// newest first
		idx := (c.recI - 1 - i + recentCap) % recentCap
		out = append(out, c.recent[idx])
	}
	return out
}

func (c *Collector) advanceQPSLocked(now int64) {
	if c.qpsEpoch == 0 {
		c.qpsEpoch = now - qpsWindowSec + 1
		return
	}
	end := c.qpsEpoch + qpsWindowSec - 1
	if now <= end {
		return
	}
	shift := now - end
	if shift >= qpsWindowSec {
		for i := range c.qpsRing {
			c.qpsRing[i] = 0
		}
		c.qpsEpoch = now - qpsWindowSec + 1
		return
	}
	var next [qpsWindowSec]uint64
	copy(next[:], c.qpsRing[shift:])
	c.qpsRing = next
	c.qpsEpoch += shift
}

func percentileLocked(c *Collector) Latency {
	n := c.latN
	if n == 0 {
		return Latency{}
	}
	vals := make([]float64, n)
	if n < latencySamples {
		copy(vals, c.latRing[:n])
	} else {
		copy(vals, c.latRing[:])
	}
	sort.Float64s(vals)
	return Latency{
		P50: percentile(vals, 50),
		P95: percentile(vals, 95),
		P99: percentile(vals, 99),
		N:   n,
	}
}

func percentile(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	idx := (p * (len(sorted) - 1)) / 100
	return sorted[idx]
}

func forwarderListLocked(c *Collector) []ForwarderHealth {
	seen := map[string]struct{}{}
	for a := range c.fwdOK {
		seen[a] = struct{}{}
	}
	for a := range c.fwdFail {
		seen[a] = struct{}{}
	}
	out := make([]ForwarderHealth, 0, len(seen))
	for a := range seen {
		out = append(out, ForwarderHealth{
			Addr:       a,
			OK:         c.fwdOK[a],
			Fail:       c.fwdFail[a],
			LastMS:     c.fwdMS[a],
			LastStatus: c.fwdLast[a],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

func topN(m map[string]uint64, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// TopBlockedNames returns up to n most frequently blocked qnames (for RPZ hot-seed).
func (c *Collector) TopBlockedNames(n int) []Count {
	if c == nil || n <= 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return topN(c.blocked, n)
}

func blockedCoverLocked(m map[string]uint64, ns []int) []CoverStat {
	if len(m) == 0 || len(ns) == 0 {
		return []CoverStat{}
	}
	ranked := topN(m, len(m))
	var total uint64
	for _, c := range ranked {
		total += c.Count
	}
	out := make([]CoverStat, 0, len(ns))
	for _, n := range ns {
		if n <= 0 {
			continue
		}
		take := n
		if take > len(ranked) {
			take = len(ranked)
		}
		var hits uint64
		for i := 0; i < take; i++ {
			hits += ranked[i].Count
		}
		pct := 0.0
		if total > 0 {
			pct = 100 * float64(hits) / float64(total)
		}
		out = append(out, CoverStat{N: n, Names: take, Hits: hits, Percent: pct})
	}
	return out
}

func trimMap(m map[string]uint64, keep int) {
	type pair struct {
		k string
		v uint64
	}
	all := make([]pair, 0, len(m))
	for k, v := range m {
		all = append(all, pair{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	for k := range m {
		delete(m, k)
	}
	for i := 0; i < len(all) && i < keep; i++ {
		m[all[i].k] = all[i].v
	}
}

func subnetOf(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	mask := net.CIDRMask(48, 128)
	n := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
	return n.String()
}

func errorKind(s Sample) string {
	if s.Timeout {
		return "timeout"
	}
	switch strings.ToUpper(s.RCode) {
	case "SERVFAIL":
		return "servfail"
	case "REFUSED":
		return "refused"
	case "FORMERR":
		return "formerr"
	case "NXDOMAIN":
		return "nxdomain"
	}
	switch s.Path {
	case "acl_denied", "ratelimited":
		return "refused"
	case "formerr":
		return "formerr"
	case "servfail", "dnssec_fail":
		return "servfail"
	}
	return ""
}
