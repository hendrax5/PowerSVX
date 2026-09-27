package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/metrics"
)

// SyncDNSDistACL mirrors allow_query/deny_query into blocklist/acl.txt; dnsdist
// maintenance() reloads it into setACL within ~1s.
func (a *API) SyncDNSDistACL() {
	if a == nil || !config.DNSDistDataplane() {
		return
	}
	allow, deny := a.srv.QueryACL()
	n, err := blockcdb.WriteDNSDistACL(a.dataDir, allow, deny)
	if err != nil {
		a.log.Warn("dnsdist acl write failed", "err", err)
		return
	}
	a.log.Info("dnsdist acl synced", "masks", n, "allow", len(allow), "deny", len(deny))
}

// StartDNSDistStatsBridge polls dnsdist web /jsonstat and feeds monitor + Prometheus
// when POWERSVX_DNS_DATAPLANE=dnsdist (edge QPS, cache, CDB self-answers).
func (a *API) StartDNSDistStatsBridge() {
	if a == nil || !config.DNSDistDataplane() {
		return
	}
	mon := a.srv.Monitor()
	base := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_WEB"))
	if base == "" {
		base = "http://127.0.0.1:8083"
	}
	base = strings.TrimRight(base, "/")
	user := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_WEB_USER"))
	if user == "" {
		user = "dontcare"
	}
	pass := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_WEB_PASSWORD"))
	if pass == "" {
		pass = "powersvx"
	}
	apiKey := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_API_KEY"))
	if apiKey == "" {
		apiKey = "powersvx-api"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	go func() {
		var (
			prevQ, prevHit, prevMiss, prevSelf float64
			have                               bool
		)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for range t.C {
			st, err := fetchDNSDistStats(client, base, user, pass, apiKey)
			if err != nil || st == nil {
				metrics.DNSDistUp.Set(0)
				continue
			}
			metrics.DNSDistUp.Set(1)
			q := st["queries"]
			hit := st["cache-hits"]
			miss := st["cache-misses"]
			self := st["self-answered"]
			metrics.DNSDistQueries.Set(q)
			metrics.DNSDistCacheHits.Set(hit)
			metrics.DNSDistCacheMisses.Set(miss)
			metrics.DNSDistSelfAnswered.Set(self)
			// dnsdist latency-avg100 is microseconds in recent builds; treat >1000 as µs.
			lat := st["latency-avg100"]
			if lat > 1000 {
				lat = lat / 1e6
			} else if lat > 10 {
				lat = lat / 1e3 // ms → s
			}
			metrics.DNSDistLatencyAvg100.Set(lat)

			if !have {
				prevQ, prevHit, prevMiss, prevSelf = q, hit, miss, self
				have = true
				continue
			}
			dq := deltaU64(q, prevQ)
			dHit := deltaU64(hit, prevHit)
			dMiss := deltaU64(miss, prevMiss)
			dSelf := deltaU64(self, prevSelf)
			prevQ, prevHit, prevMiss, prevSelf = q, hit, miss, self

			// Partition edge QPS: spoof + packet-cache + remainder (backend).
			// Do not add cache-misses into the same total as queries (overlaps self-answered).
			if dSelf > 0 {
				if mon != nil {
					mon.RecordPathOnly("rpz", dSelf)
					mon.RecordBulk("dnsdist_spoof", dSelf)
				}
				metrics.QueriesTotal.WithLabelValues("dnsdist", "blocked").Add(float64(dSelf))
				metrics.RPZBlocked.Add(float64(dSelf))
			}
			if dHit > 0 {
				if mon != nil {
					mon.RecordBulk("dnsdist_cache", dHit)
				}
				metrics.QueriesTotal.WithLabelValues("dnsdist", "cache").Add(float64(dHit))
				metrics.CacheHits.Add(float64(dHit))
			}
			var backend uint64
			if dq > dSelf+dHit {
				backend = dq - dSelf - dHit
			}
			if backend > 0 {
				if mon != nil {
					mon.RecordBulk("dnsdist", backend)
				}
				metrics.QueriesTotal.WithLabelValues("dnsdist", "ok").Add(float64(backend))
			}
			if dMiss > 0 {
				metrics.QueriesTotal.WithLabelValues("dnsdist", "miss").Add(float64(dMiss))
				metrics.CacheMisses.Add(float64(dMiss))
			}
		}
	}()
	a.log.Info("dnsdist stats bridge started", "url", base+"/jsonstat", "interval", "1s")
}

func deltaU64(cur, prev float64) uint64 {
	if cur < prev {
		return 0
	}
	return uint64(cur - prev)
}

func fetchDNSDistStats(client *http.Client, base, user, pass, apiKey string) (map[string]float64, error) {
	req, err := http.NewRequest(http.MethodGet, base+"/jsonstat?command=stats", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(user, pass)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("dnsdist jsonstat HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]float64, len(raw))
	for k, v := range raw {
		switch t := v.(type) {
		case float64:
			out[k] = t
		case json.Number:
			f, _ := t.Float64()
			out[k] = f
		}
	}
	return out, nil
}
