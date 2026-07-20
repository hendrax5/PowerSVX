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

	CacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "powersvx_cache_hits_total",
		Help: "Cache hits",
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
)

func Handler() http.Handler {
	return promhttp.Handler()
}
