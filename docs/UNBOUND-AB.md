# A/B proof: PowerSVX vs Unbound

Use this checklist before cutting customer traffic from Unbound (e.g. `103.172.70.254`) to PowerSVX.

## Goal gates (same offered customer load ~4.5–6k QPS)

| Metrik | Unbound baseline | PowerSVX must |
|--------|------------------|---------------|
| Offered QPS (no retry storm) | ~4.6k | ~4.5–6k (not 30k+) |
| Cache hit+stale | ~88% | ≥90% |
| Slow path | ~540 recursive/s | ≤600/s; fallback &lt;5% of resolve |
| Queue | reqlist avg~60 max~95 | inflight avg&lt;80 max&lt;150 |
| Host load (16 core) | ~0.6 | &lt;2 |
| Cache p95 | fast | &lt;5ms |
| Miss p95 | — | &lt;400ms |
| RAM | — | ≤2 GB |

Also beat Unbound on **at least 3 of**: load, miss p95, inflight max, RSS, fallback rate.

## How to run (15–30 min)

1. Forward a **subset** of the same customer nets to PowerSVX (mirror Unbound ACL).
2. On PowerSVX host:
   ```bash
   ./scripts/ab-vs-unbound.sh http://127.0.0.1:9100/metrics
   ```
3. On Unbound host, note live stats: queries/s, cachehits, recursive, reqlist, loadavg.
4. Compare side-by-side for 15–30 minutes under steady traffic.
5. Only raise cutover share after gates pass.

## Metrics to watch (PowerSVX)

- `powersvx_resolve_inflight`
- `rate(powersvx_admit_rejected_total[1m])`
- `rate(powersvx_query_duration_by_path_seconds_count[1m])` by `path`
- `powersvx_cache_hits_total` + `powersvx_cache_stale_hits_total`
- `rate(powersvx_queries_total[1m])` (watch for retry inflation)
- Grafana dashboard **PowerSVX DNS** (updated Unbound-comparable panels)

## Config knobs that must be live

- **`resolver mode = recursive`** (forward is optional only)
- `max_inflight = 1024` (fail-fast admit)
- `global_qps ≈ 7500`
- `min_ttl = 120`, `serve_stale = true`, `stale_ttl = 60`, `prefetch_pct = 10`
- Query ACL / firewall aligned with Unbound allow lists
- `query_log_sample_rate = 0.05` when query log enabled
