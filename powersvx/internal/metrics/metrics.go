// Package metrics exposes LOW-CARDINALITY counters only (Phase 3). Observability
// is treated as a CPU budget: no per-qname / per-client / per-upstream labels
// that would explode cardinality and cost. Counters are plain atomics on the
// hot path and rendered lazily in a Prometheus-compatible text format.
package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type Metrics struct {
	Queries       uint64
	CacheHits     uint64
	CacheMisses   uint64
	RPZBlocks     uint64
	UpstreamErr   uint64
	ServFail      uint64
	NXDomain      uint64
	TCPQueries    uint64
	Coalesced     uint64 // singleflight-shared upstream lookups
	LogsDropped   uint64
	enabled       bool
	logsDroppedFn func() uint64
}

func New(enabled bool) *Metrics { return &Metrics{enabled: enabled} }

func (m *Metrics) IncQueries()     { atomic.AddUint64(&m.Queries, 1) }
func (m *Metrics) IncCacheHit()    { atomic.AddUint64(&m.CacheHits, 1) }
func (m *Metrics) IncCacheMiss()   { atomic.AddUint64(&m.CacheMisses, 1) }
func (m *Metrics) IncRPZBlock()    { atomic.AddUint64(&m.RPZBlocks, 1) }
func (m *Metrics) IncUpstreamErr() { atomic.AddUint64(&m.UpstreamErr, 1) }
func (m *Metrics) IncServFail()    { atomic.AddUint64(&m.ServFail, 1) }
func (m *Metrics) IncNXDomain()    { atomic.AddUint64(&m.NXDomain, 1) }
func (m *Metrics) IncTCP()         { atomic.AddUint64(&m.TCPQueries, 1) }
func (m *Metrics) IncCoalesced()   { atomic.AddUint64(&m.Coalesced, 1) }

// BindLogsDropped wires a callback so the async logger's drop counter shows up
// in /metrics without coupling packages.
func (m *Metrics) BindLogsDropped(fn func() uint64) { m.logsDroppedFn = fn }

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		g := func(name, help string, v uint64) {
			fmt.Fprintf(w, "# HELP powersvx_%s %s\n# TYPE powersvx_%s counter\npowersvx_%s %d\n",
				name, help, name, name, v)
		}
		g("queries_total", "Total DNS queries received", atomic.LoadUint64(&m.Queries))
		g("cache_hits_total", "Cache hits", atomic.LoadUint64(&m.CacheHits))
		g("cache_misses_total", "Cache misses", atomic.LoadUint64(&m.CacheMisses))
		g("rpz_blocks_total", "Queries blocked by RPZ", atomic.LoadUint64(&m.RPZBlocks))
		g("upstream_errors_total", "Upstream exchange errors", atomic.LoadUint64(&m.UpstreamErr))
		g("servfail_total", "SERVFAIL responses returned", atomic.LoadUint64(&m.ServFail))
		g("nxdomain_total", "NXDOMAIN responses", atomic.LoadUint64(&m.NXDomain))
		g("tcp_queries_total", "Queries served over TCP", atomic.LoadUint64(&m.TCPQueries))
		g("coalesced_total", "Upstream lookups coalesced by singleflight", atomic.LoadUint64(&m.Coalesced))
		if m.logsDroppedFn != nil {
			g("logs_dropped_total", "Log lines dropped by backpressure", m.logsDroppedFn())
		}
	})
}
