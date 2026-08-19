package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	QueriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "powersvx_queries_total",
		Help: "Total DNS queries",
	}, []string{"protocol", "status"})

	QueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "powersvx_query_duration_seconds",
		Help:    "DNS query latency",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	}, []string{"protocol"})

	QueryDurationByPath = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "powersvx_query_duration_by_path_seconds",
		Help:    "DNS query latency by resolve path (cache, recursive, fallback, forward, …)",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	}, []string{"path"})

	ResolveInflight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_resolve_inflight",
		Help: "In-flight recursive/forward resolves",
	})

	AdmitRejected = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_admit_rejected_total",
		Help: "Resolves rejected because max_inflight was full (fail-fast)",
	})

	CacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_cache_hits_total",
		Help: "Cache hits",
	})

	CacheStaleHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_cache_stale_hits_total",
		Help: "Serve-stale cache hits (expired but within stale window)",
	})

	CachePrefetch = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_cache_prefetch_total",
		Help: "Background cache prefetch/refresh starts",
	})

	CacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_cache_misses_total",
		Help: "Cache misses",
	})

	RPZBlocked = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_rpz_blocked_total",
		Help: "Queries blocked by RPZ",
	})

	RateLimited = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_rate_limited_total",
		Help: "Queries dropped by rate limiter",
	})

	ACLSilentDrop = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_acl_silent_drop_total",
		Help: "ACL-denied queries silently dropped after autoban (no REFUSED reply)",
	})

	ACLAutoban = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_acl_autoban_total",
		Help: "ACL-denied client IPs autobanned (silent drop / nft)",
	})

	AggressiveNSEC = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_aggressive_nsec_total",
		Help: "NXDOMAIN answers synthesized from a cached NSEC gap (RFC 8198)",
	})

	ForwarderAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "powersvx_forwarder_attempts_total",
		Help: "Outbound forwarder attempts",
	}, []string{"addr", "result"})

	Goroutines = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_goroutines",
		Help: "Process goroutine count",
	})

	RSSBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_process_rss_bytes",
		Help: "Process resident set size in bytes",
	})
)

func Handler() http.Handler {
	return promhttp.Handler()
}
