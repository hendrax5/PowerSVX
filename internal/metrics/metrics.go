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

	UnboundQueries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_unbound_queries_total",
		Help: "Unbound total.num.queries (dataplane cumulative)",
	})
	UnboundCacheHits = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_unbound_cache_hits",
		Help: "Unbound total.num.cachehits (dataplane cumulative)",
	})
	UnboundCacheMisses = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_unbound_cache_misses",
		Help: "Unbound total.num.cachemiss (dataplane cumulative)",
	})
	UnboundRecursionAvg = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_unbound_recursion_time_avg_seconds",
		Help: "Unbound total.recursion.time.avg",
	})
	UnboundRecursionMedian = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_unbound_recursion_time_median_seconds",
		Help: "Unbound total.recursion.time.median",
	})
	UnboundRequestlistAvg = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_unbound_requestlist_avg",
		Help: "Unbound total.requestlist.avg",
	})
	UnboundMemCacheRRset = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_unbound_mem_cache_rrset_bytes",
		Help: "Unbound mem.cache.rrset",
	})
	UnboundMemCacheMsg = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_unbound_mem_cache_message_bytes",
		Help: "Unbound mem.cache.message",
	})
	UnboundUp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_unbound_up",
		Help: "1 when unbound-control stats succeeded",
	})

	HostMemAvailableBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_host_mem_available_bytes",
		Help: "Host MemAvailable from /proc/meminfo",
	})
	HostMemTotalBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_host_mem_total_bytes",
		Help: "Host MemTotal from /proc/meminfo",
	})
	HostDiskUsedPercent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_host_disk_used_percent",
		Help: "Host root filesystem used percent",
	})
	HostLoad1 = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_host_load1",
		Help: "Host load average 1m",
	})

	DNSDistUp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_dnsdist_up",
		Help: "1 when dnsdist web /jsonstat succeeded",
	})
	DNSDistQueries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_dnsdist_queries",
		Help: "dnsdist cumulative queries",
	})
	DNSDistCacheHits = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_dnsdist_cache_hits",
		Help: "dnsdist cumulative packet-cache hits",
	})
	DNSDistCacheMisses = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_dnsdist_cache_misses",
		Help: "dnsdist cumulative packet-cache misses",
	})
	DNSDistSelfAnswered = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_dnsdist_self_answered",
		Help: "dnsdist cumulative self-answered (includes CDB spoof)",
	})
	DNSDistLatencyAvg100 = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "powersvx_dnsdist_latency_avg100_seconds",
		Help: "dnsdist latency-avg100 (converted to seconds)",
	})
)

func Handler() http.Handler {
	return promhttp.Handler()
}
