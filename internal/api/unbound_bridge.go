package api

import (
	"time"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/metrics"
	"github.com/powersvx/powersvx/internal/unboundrpz"
)

// StartUnboundStatsBridge polls the Unbound backend (127.0.0.1:5353 behind dnsdist) and
// exports its counters to Prometheus. The dashboard QPS comes from dnsdist.
func (a *API) StartUnboundStatsBridge() {
	if a == nil || !config.DNSDistDataplane() {
		return
	}
	go func() {
		var (
			prevQ, prevHit, prevMiss float64
			have                     bool
		)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for range t.C {
			st, err := unboundrpz.Stats()
			if err != nil || len(st) == 0 {
				metrics.UnboundUp.Set(0)
				continue
			}
			metrics.UnboundUp.Set(1)
			q := st["total.num.queries"]
			hit := st["total.num.cachehits"]
			miss := st["total.num.cachemiss"]
			metrics.UnboundQueries.Set(q)
			metrics.UnboundCacheHits.Set(hit)
			metrics.UnboundCacheMisses.Set(miss)
			metrics.UnboundRecursionAvg.Set(st["total.recursion.time.avg"])
			metrics.UnboundRecursionMedian.Set(st["total.recursion.time.median"])
			metrics.UnboundRequestlistAvg.Set(st["total.requestlist.avg"])
			metrics.UnboundMemCacheRRset.Set(st["mem.cache.rrset"])
			metrics.UnboundMemCacheMsg.Set(st["mem.cache.message"])
			if !have {
				prevQ, prevHit, prevMiss = q, hit, miss
				have = true
				continue
			}
			dq := uint64(0)
			if q >= prevQ {
				dq = uint64(q - prevQ)
			}
			dHit := uint64(0)
			if hit >= prevHit {
				dHit = uint64(hit - prevHit)
			}
			dMiss := uint64(0)
			if miss >= prevMiss {
				dMiss = uint64(miss - prevMiss)
			}
			prevQ, prevHit, prevMiss = q, hit, miss

			if dHit > 0 {
				metrics.QueriesTotal.WithLabelValues("unbound", "cache").Add(float64(dHit))
				metrics.CacheHits.Add(float64(dHit))
			}
			if dMiss > 0 {
				metrics.QueriesTotal.WithLabelValues("unbound", "miss").Add(float64(dMiss))
				metrics.CacheMisses.Add(float64(dMiss))
			}
			// If Unbound reports queries without splitting hit/miss cleanly, fill the gap.
			accounted := dHit + dMiss
			if dq > accounted {
				metrics.QueriesTotal.WithLabelValues("unbound", "ok").Add(float64(dq - accounted))
			}
		}
	}()
	a.log.Info("unbound stats bridge started", "interval", "1s")
}
