package api

import (
	"time"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/metrics"
	"github.com/powersvx/powersvx/internal/unboundrpz"
)

// StartUnboundStatsBridge polls Unbound stats and feeds the dashboard monitor + Prometheus
// so QPS/cache charts keep working when Go is not on the DNS hot path.
// Runs for unbound dataplane (:53) and dnsdist dataplane (Unbound backend :5353).
func (a *API) StartUnboundStatsBridge() {
	if a == nil || !config.FilterDataplane() {
		return
	}
	mon := a.srv.Monitor()
	if mon == nil {
		return
	}
	go func() {
		var (
			prevQ, prevHit, prevMiss, prevRPZ float64
			have                              bool
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
			rpz := unboundrpz.RPZActionTotal(st)
			metrics.UnboundQueries.Set(q)
			metrics.UnboundCacheHits.Set(hit)
			metrics.UnboundCacheMisses.Set(miss)
			metrics.UnboundRPZActions.Set(rpz)
			metrics.UnboundRecursionAvg.Set(st["total.recursion.time.avg"])
			metrics.UnboundRecursionMedian.Set(st["total.recursion.time.median"])
			metrics.UnboundRequestlistAvg.Set(st["total.requestlist.avg"])
			metrics.UnboundMemCacheRRset.Set(st["mem.cache.rrset"])
			metrics.UnboundMemCacheMsg.Set(st["mem.cache.message"])
			if !have {
				prevQ, prevHit, prevMiss, prevRPZ = q, hit, miss, rpz
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
			dRPZ := uint64(0)
			if rpz >= prevRPZ {
				dRPZ = uint64(rpz - prevRPZ)
			}
			prevQ, prevHit, prevMiss, prevRPZ = q, hit, miss, rpz

			// Live UI monitor: only when Unbound owns public :53. On dnsdist, edge bridge owns QPS.
			feedMon := config.UnboundDataplane()
			if dHit > 0 {
				if feedMon {
					mon.RecordBulk("unbound_cache", dHit)
				}
				metrics.QueriesTotal.WithLabelValues("unbound", "cache").Add(float64(dHit))
				metrics.CacheHits.Add(float64(dHit))
			}
			if dMiss > 0 {
				if feedMon {
					mon.RecordBulk("unbound_recurse", dMiss)
				}
				metrics.QueriesTotal.WithLabelValues("unbound", "miss").Add(float64(dMiss))
				metrics.CacheMisses.Add(float64(dMiss))
			}
			// If Unbound reports queries without splitting hit/miss cleanly, fill the gap.
			accounted := dHit + dMiss
			if dq > accounted {
				if feedMon {
					mon.RecordBulk("unbound", dq-accounted)
				}
				metrics.QueriesTotal.WithLabelValues("unbound", "ok").Add(float64(dq - accounted))
			}
			if dRPZ > 0 {
				if feedMon {
					mon.RecordPathOnly("rpz", dRPZ)
				}
				metrics.RPZBlocked.Add(float64(dRPZ))
			}
		}
	}()
	a.log.Info("unbound stats bridge started", "interval", "1s")
}
