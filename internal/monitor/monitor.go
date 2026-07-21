package monitor

import (
	"fmt"
	"net"
	"runtime"
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
	Latency     time.Duration
	Path        string // cache, auth, recursive, forward, fallback, acl_denied, ratelimited, ...
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
	aclAllow uint64
	aclDeny  uint64
	rlHits   map[string]uint64
	rlTotal  uint64

	latRing [latencySamples]float64 // milliseconds
	latN    int
	latI    int

	fwdOK   map[string]uint64
	fwdFail map[string]uint64
	fwdLast map[string]string
	fwdMS   map[string]int64
}

func New() *Collector {
	now := time.Now().Unix()
	return &Collector{
		clients:  make(map[string]uint64),
		subnets:  make(map[string]uint64),
		paths:    make(map[string]uint64),
		errors:   make(map[string]uint64),
		rlHits:   make(map[string]uint64),
		fwdOK:    make(map[string]uint64),
		fwdFail:  make(map[string]uint64),
		fwdLast:  make(map[string]string),
		fwdMS:    make(map[string]int64),
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

	if s.ACLDenied || path == "acl_denied" {
		c.aclDeny++
	} else {
		c.aclAllow++
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
}

type Snapshot struct {
	QPSNow           float64           `json:"qps_now"`
	QPSSeries        []Point           `json:"qps_series"`
	TopClients       []Count           `json:"top_clients"`
	TopSubnets       []Count           `json:"top_subnets"`
	Latency          Latency           `json:"latency"`
	Paths            []Count           `json:"paths"`
	Errors           []Count           `json:"errors"`
	ACLAllow         uint64            `json:"acl_allow"`
	ACLDeny          uint64            `json:"acl_deny"`
	ACLOpenResolver  bool              `json:"acl_open_resolver"`
	RateLimitedTotal uint64            `json:"rate_limited_total"`
	RateLimitTop     []Count           `json:"rate_limit_top"`
	RateLimitActive  []Count           `json:"rate_limit_active"`
	Forwarders       []ForwarderHealth `json:"forwarders"`
	Resources        Resources         `json:"resources"`
}

func (c *Collector) Snapshot(allowCIDRs []string, activeBlocked []Count) Snapshot {
	out := Snapshot{
		QPSSeries:       []Point{},
		TopClients:      []Count{},
		TopSubnets:      []Count{},
		Paths:           []Count{},
		Errors:          []Count{},
		RateLimitTop:    []Count{},
		RateLimitActive: activeBlocked,
		Forwarders:      []ForwarderHealth{},
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
	out.Paths = topN(c.paths, 20)
	out.Errors = topN(c.errors, 20)
	out.ACLAllow = c.aclAllow
	out.ACLDeny = c.aclDeny
	out.RateLimitedTotal = c.rlTotal
	out.RateLimitTop = topN(c.rlHits, 10)
	out.Latency = percentileLocked(c)
	out.Forwarders = forwarderListLocked(c)
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

func resourceSnapshot() Resources {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return Resources{
		Goroutines: runtime.NumGoroutine(),
		AllocMB:    float64(ms.Alloc) / (1024 * 1024),
		SysMB:      float64(ms.Sys) / (1024 * 1024),
		HeapMB:     float64(ms.HeapAlloc) / (1024 * 1024),
		NumGC:      ms.NumGC,
	}
}
