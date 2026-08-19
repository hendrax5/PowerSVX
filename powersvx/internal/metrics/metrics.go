// Package metrics exposes LOW-CARDINALITY counters plus a bounded-bucket latency
// histogram. Observability is treated as a CPU budget: no per-qname/client
// labels. Counters are plain atomics; the histogram uses fixed buckets and
// atomic bucket counts so p50/p95/p99 can be read straight from /metrics.
package metrics

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"sync/atomic"
	"time"
)

type Metrics struct {
	Queries     uint64
	CacheHits   uint64
	CacheMisses uint64
	RPZBlocks   uint64
	UpstreamErr uint64
	ServFail    uint64
	NXDomain    uint64
	TCPQueries  uint64
	Coalesced   uint64
	Prefetches  uint64
	ServedStale  uint64
	DNSSECSecure uint64
	DNSSECBogus  uint64
	LogsDropped uint64

	enabled       bool
	lat           *Histogram
	logsDroppedFn func() uint64
	upstreamsFn   func() []UpstreamStat
}

type UpstreamStat struct {
	Addr       string
	Up         bool
	RTTSeconds float64
}

func New(enabled bool) *Metrics {
	return &Metrics{enabled: enabled, lat: newHistogram()}
}

func (m *Metrics) IncQueries()     { atomic.AddUint64(&m.Queries, 1) }
func (m *Metrics) IncCacheHit()    { atomic.AddUint64(&m.CacheHits, 1) }
func (m *Metrics) IncCacheMiss()   { atomic.AddUint64(&m.CacheMisses, 1) }
func (m *Metrics) IncRPZBlock()    { atomic.AddUint64(&m.RPZBlocks, 1) }
func (m *Metrics) IncUpstreamErr() { atomic.AddUint64(&m.UpstreamErr, 1) }
func (m *Metrics) IncServFail()    { atomic.AddUint64(&m.ServFail, 1) }
func (m *Metrics) IncNXDomain()    { atomic.AddUint64(&m.NXDomain, 1) }
func (m *Metrics) IncTCP()         { atomic.AddUint64(&m.TCPQueries, 1) }
func (m *Metrics) IncCoalesced()   { atomic.AddUint64(&m.Coalesced, 1) }
func (m *Metrics) IncPrefetch()    { atomic.AddUint64(&m.Prefetches, 1) }
func (m *Metrics) IncServedStale()   { atomic.AddUint64(&m.ServedStale, 1) }
func (m *Metrics) IncDNSSECSecure()  { atomic.AddUint64(&m.DNSSECSecure, 1) }
func (m *Metrics) IncDNSSECBogus()   { atomic.AddUint64(&m.DNSSECBogus, 1) }

// ObserveLatency records server-side handling time for the latency histogram.
func (m *Metrics) ObserveLatency(d time.Duration) { m.lat.Observe(d) }

func (m *Metrics) BindLogsDropped(fn func() uint64)         { m.logsDroppedFn = fn }
func (m *Metrics) BindUpstreams(fn func() []UpstreamStat)   { m.upstreamsFn = fn }

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
		g("prefetches_total", "Background cache refreshes performed", atomic.LoadUint64(&m.Prefetches))
		g("served_stale_total", "Stale answers served during upstream failure (RFC 8767)", atomic.LoadUint64(&m.ServedStale))
		g("dnssec_secure_total", "Answers validated Secure", atomic.LoadUint64(&m.DNSSECSecure))
		g("dnssec_bogus_total", "Answers rejected Bogus (SERVFAIL)", atomic.LoadUint64(&m.DNSSECBogus))
		if m.logsDroppedFn != nil {
			g("logs_dropped_total", "Log lines dropped by backpressure", m.logsDroppedFn())
		}

		// Latency histogram (Prometheus-compatible) + convenience quantile gauges.
		m.lat.render(w)

		// Per-upstream health/latency (low cardinality: a handful of upstreams).
		if m.upstreamsFn != nil {
			stats := m.upstreamsFn()
			fmt.Fprintf(w, "# HELP powersvx_upstream_up Upstream health (1=up,0=down)\n# TYPE powersvx_upstream_up gauge\n")
			for _, s := range stats {
				up := 0
				if s.Up {
					up = 1
				}
				fmt.Fprintf(w, "powersvx_upstream_up{addr=%q} %d\n", s.Addr, up)
			}
			fmt.Fprintf(w, "# HELP powersvx_upstream_rtt_seconds EWMA upstream RTT\n# TYPE powersvx_upstream_rtt_seconds gauge\n")
			for _, s := range stats {
				fmt.Fprintf(w, "powersvx_upstream_rtt_seconds{addr=%q} %g\n", s.Addr, s.RTTSeconds)
			}
		}
	})
}

// Histogram is a fixed-bucket latency histogram with atomic bucket counts.
type Histogram struct {
	bounds []float64 // upper bounds in seconds (ascending)
	counts []uint64  // atomic; len == len(bounds)+1 (last is +Inf)
	sumNs  uint64    // atomic
	count  uint64    // atomic
}

var latencyBounds = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
	0.1, 0.25, 0.5, 1, 2.5, 5,
}

func newHistogram() *Histogram {
	return &Histogram{bounds: latencyBounds, counts: make([]uint64, len(latencyBounds)+1)}
}

func (h *Histogram) Observe(d time.Duration) {
	sec := d.Seconds()
	i := sort.SearchFloat64s(h.bounds, sec)
	atomic.AddUint64(&h.counts[i], 1)
	atomic.AddUint64(&h.count, 1)
	atomic.AddUint64(&h.sumNs, uint64(d.Nanoseconds()))
}

// Quantile estimates the q-th percentile using linear interpolation within the
// bucket that contains it (Prometheus-style), giving a precise value instead of
// a bucket edge.
func (h *Histogram) Quantile(q float64) float64 {
	total := atomic.LoadUint64(&h.count)
	if total == 0 {
		return 0
	}
	target := q * float64(total)
	var cum float64
	lower := 0.0
	for i, upper := range h.bounds {
		c := float64(atomic.LoadUint64(&h.counts[i]))
		if cum+c >= target {
			if c == 0 {
				return upper
			}
			frac := (target - cum) / c
			return lower + (upper-lower)*frac
		}
		cum += c
		lower = upper
	}
	return h.bounds[len(h.bounds)-1] // in +Inf bucket: clamp to last finite bound
}

func (h *Histogram) render(w http.ResponseWriter) {
	fmt.Fprintf(w, "# HELP powersvx_query_duration_seconds Server-side handling latency\n# TYPE powersvx_query_duration_seconds histogram\n")
	var cum uint64
	for i, b := range h.bounds {
		cum += atomic.LoadUint64(&h.counts[i])
		fmt.Fprintf(w, "powersvx_query_duration_seconds_bucket{le=\"%g\"} %d\n", b, cum)
	}
	total := atomic.LoadUint64(&h.count)
	fmt.Fprintf(w, "powersvx_query_duration_seconds_bucket{le=\"+Inf\"} %d\n", total)
	fmt.Fprintf(w, "powersvx_query_duration_seconds_sum %g\n", float64(atomic.LoadUint64(&h.sumNs))/1e9)
	fmt.Fprintf(w, "powersvx_query_duration_seconds_count %d\n", total)

	// Convenience quantile gauges (read tail latency without a load tool).
	q := func(name string, v float64) {
		if math.IsInf(v, 0) {
			v = h.bounds[len(h.bounds)-1]
		}
		fmt.Fprintf(w, "# TYPE powersvx_query_duration_%s_seconds gauge\npowersvx_query_duration_%s_seconds %g\n", name, name, v)
	}
	q("p50", h.Quantile(0.50))
	q("p95", h.Quantile(0.95))
	q("p99", h.Quantile(0.99))
}
