# PowerSVX — Hardened DNS Resolver (Performance Mode)

Recursive/forwarding + cache resolver with millions-scale RPZ, engineered for
throughput-per-resource on modest hardware (2 core / 4 GB / 1G NIC). This
implements the hardened optimization plan: a strict **Performance Mode** that
keeps only the classic UDP/TCP + recursive/forwarding + cache + RPZ on the hot
path and treats observability as a CPU budget.

## Why this beats a features-on-by-default resolver

| Concern (from the plan) | How PowerSVX addresses it |
|---|---|
| RPZ millions of rules too expensive | Immutable, cache-friendly sorted-blob suffix matcher (2 GC pointers total). Allocation-free lookup. **Atomic swap** on daily update — never mutate a serving structure. |
| Observability in the hot path | Low-cardinality atomic counters only (no per-qname/client labels). Query logging is **off by default**, and when on it is **sampled + async + bounded (drop policy)**. |
| Small per-query allocs / GC pressure | Per-worker reusable read buffers; compact hand-built cache keys; no `fmt` on hot path. |
| Shared cache lock contention | **Sharded** cache (N independent-mutex shards) with separate positive/negative handling. |
| Goroutine/channel churn | **No goroutine-per-request** for UDP: SO_REUSEPORT + one worker loop per socket. |
| Duplicate upstream work on identical misses | **singleflight** coalescing per cache key. |
| TCP fallback spike on truncation | UDP responses truncated to advertised size (TC bit) + upstream TCP fallback. |
| Kernel/runtime tuning | `SO_REUSEPORT`, tunable `SO_RCVBUF/SNDBUF`, `scripts/tune.sh` sysctls, `GOMAXPROCS`. |

## Layout

```
cmd/powersvx   resolver server entrypoint
cmd/bench      Phase-1 UDP load generator (QPS + p50/p95/p99 + rcodes)
internal/rpz       immutable suffix/exact matcher + atomic swap
internal/cache     sharded positive/negative answer cache (+ hot-entry prefetch)
internal/resolver  hot path: rpz -> cache -> singleflight -> resolve
internal/upstream  health-checked, latency-ranked forwarding pool (failover)
internal/recursive optional iterative resolver from root hints
internal/server    SO_REUSEPORT UDP workers + recvmmsg/sendmmsg batch (v4/v6) + TCP
internal/dnspool   sync.Pool reuse for dns.Msg + packing buffers
internal/metrics   low-cardinality counters + latency histogram (p50/p95/p99)
internal/logx      async sampled bounded logger
config/            performance.yaml, general.yaml, rpz.sample.list
scripts/tune.sh    Phase-4 kernel/sysctl tuning
```

## Build & run

```bash
cd powersvx
go build ./...
go build -o bin/powersvx ./cmd/powersvx
go build -o bin/bench    ./cmd/bench

# Performance mode (binds :5354 by default so it runs without root)
./bin/powersvx -config config/performance.yaml
```

Test a query:

```bash
dig @127.0.0.1 -p 5354 example.com A
```

## Backend modes

Set in the YAML:

```yaml
recursion: false        # false = forward to upstreams (default); true = built-in recursive
recursion_ipv6: false   # allow IPv6 roots/glue when recursion is on
dnssec_validate: false  # heavier mode: validate answers vs root anchor (recursive only)
health:                 # forwarding-pool health checks (failover)
  max_fails: 3          # consecutive failures before an upstream is demoted
  probe_interval_seconds: 10  # cadence for reviving down upstreams
```

- Forwarding pool: queries hit a lock-free ranked snapshot (healthy first, lowest
  EWMA latency first). A dead/slow upstream is demoted after `max_fails` and
  skipped; a background prober revives it. Per-upstream health/RTT show up in
  `/metrics` as `powersvx_upstream_up{addr=...}` and `powersvx_upstream_rtt_seconds`.
- Recursive: iterative resolution from embedded root hints (root -> TLD -> auth),
  following referrals/glue and chasing CNAMEs. A **delegation cache** remembers
  NS/glue per zone so cold misses don't re-walk from the root each time (DS
  queries correctly start at the parent).
- DNSSEC (`dnssec_validate: true`, recursive only): builds a chain of trust from
  the root KSK anchor to the answer's signer zone. Positive answers and **secure
  denial of existence** (NSEC and NSEC3, incl. NSEC3 closest-encloser) are
  validated: Secure ⇒ AD bit, cryptographically broken ⇒ SERVFAIL
  (`powersvx_dnssec_bogus_total`), unsigned ⇒ Insecure.
- Aggressive NSEC (RFC 8198): validated NSEC gaps are cached and used to
  synthesize NXDOMAIN locally for any name inside a proven gap, absorbing
  random-subdomain floods (`powersvx_aggressive_nsec_total`). NSEC only.

## EDNS Client Subnet (ECS)

With `ecs.enabled: true`, the resolver passes a client-provided ECS through to
upstreams, or synthesizes one from the client IP masked to `v4_prefix`/`v6_prefix`,
so CDNs return geo-correct answers. ECS-scoped answers are cached per subnet.

## Live reload (SIGHUP)

`kill -HUP` reloads the config and hot-swaps, without a restart: RPZ zone,
upstream list (`pool.SetServers`), TTL clamps, and serve-stale settings.

## Serve-stale (RFC 8767)

With `cache.serve_stale: true`, if live resolution fails the resolver answers
from an expired-but-retained cache entry (short `serve_stale_ttl`, retained up to
`serve_stale_max_seconds`) instead of SERVFAIL, so brief upstream blips don't
break clients. Counted as `powersvx_served_stale_total`.

## Latency without the load tool

`/metrics` exposes a bounded-bucket histogram plus convenience gauges so you can
watch tail latency directly:

```
powersvx_query_duration_seconds_bucket{le="..."}  # cumulative buckets
powersvx_query_duration_seconds_sum / _count
powersvx_query_duration_p50_seconds
powersvx_query_duration_p95_seconds
powersvx_query_duration_p99_seconds
```

## Phase 1 — baseline & isolate the bottleneck

Micro-benchmarks (RPZ at 1M rules, cache under parallel load):

```bash
go test ./internal/rpz  -bench . -benchmem -run x
go test ./internal/cache -bench . -benchmem -run x
```

Live load + profiles (pprof is enabled in the sample config):

```bash
# terminal 1
./bin/powersvx -config config/performance.yaml
# terminal 2 — pick a path
./bin/bench -server 127.0.0.1:5354 -mode hit  -c 100 -d 20s   # cache-hit
./bin/bench -server 127.0.0.1:5354 -mode miss -c 100 -d 20s   # cache-miss/upstream
./bin/bench -server 127.0.0.1:5354 -mode nx   -c 100 -d 20s   # random-subdomain flood
# terminal 3 — capture where CPU/contention actually goes
go tool pprof  http://127.0.0.1:6060/debug/pprof/profile?seconds=20   # CPU
go tool pprof  http://127.0.0.1:6060/debug/pprof/allocs               # alloc
go tool pprof  http://127.0.0.1:6060/debug/pprof/mutex                # contention
go tool pprof  http://127.0.0.1:6060/debug/pprof/block                # blocking
```

Compare metrics/logging ON vs OFF by toggling `logging.enabled` /
`metrics.enabled` in the YAML and re-running the same load.

## Phase 5 — fair comparison vs PowerDNS/Technitium

Run each competitor with the same upstreams and blocklist, then drive all with
`cmd/bench` under the same scenarios: 90% hit + RPZ, 50% mixed A/AAAA/TXT,
random-subdomain/NX flood, UDP-dominant + some TCP. Key metrics: sustainable QPS
before p99 breaks, CPU per 10k QPS, stable memory footprint, drop/SERVFAIL rate.
`/metrics` on `127.0.0.1:9153` exposes the counters.

## Decisions taken (open questions in the plan)

- **DNSSEC**: OFF in performance mode by default (`dnssec: false`); it changes
  the whole perf profile. Enable explicitly if validation is mandatory.
- **Query logging at high QPS**: OFF by default; when enabled it is sampled
  (`sample_rate`) + async + bounded with a drop policy — never unbounded.
- **RPZ scope**: fast **exact + domain-suffix** only. RR-based/heavier policies
  are intentionally out of the hot path.

## Daily RPZ update (snapshot + atomic swap)

Point `rpz.files` at your updated lists and send `SIGHUP`:

```bash
kill -HUP $(pgrep -f powersvx)
```

The new zone is built off the hot path and swapped in atomically; if the build
fails the old zone keeps serving.
