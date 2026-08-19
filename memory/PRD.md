# PowerSVX — Hardened DNS Resolver (Performance Mode)

## Problem statement
Optimize a recursive/forwarding + cache DNS resolver with millions-scale RPZ for
throughput-per-resource on modest HW (2 core / 4 GB / 1G NIC). No existing
codebase or repo link was provided, so a clean Go implementation of the hardened
plan (Phases 1–4) was built from scratch. Language: Go 1.23.

## Architecture (dir: /app/powersvx)
- internal/rpz: immutable sorted-blob suffix/exact matcher (blob []byte + []uint32
  offsets = 2 GC pointers regardless of rule count); allocation-free lookup;
  atomic-swap updates (SIGHUP), never mutate a serving zone.
- internal/cache: sharded (N-mutex) answer cache; positive + negative; TTL aging;
  bounded per-shard eviction.
- internal/resolver: hot path RPZ -> cache -> singleflight -> upstream forward
  (UDP + TCP fallback on truncation).
- internal/server: SO_REUSEPORT UDP workers (one recv/process/send loop each, no
  goroutine-per-request, reusable buffers) + TCP listener; SO_RCVBUF/SNDBUF tuning.
- internal/metrics: low-cardinality atomic counters, Prometheus text on :9153.
- internal/logx: async, sampled, bounded logger with drop policy.
- cmd/powersvx: server entrypoint (+ pprof CPU/alloc/mutex/block).
- cmd/bench: Phase-1 load generator (hit/miss/nx/mixed, QPS + p50/p95/p99 + rcodes).
- config/performance.yaml, config/general.yaml, config/rpz.sample.list, scripts/tune.sh.

## Design decisions on open questions
- DNSSEC: OFF by default in performance mode (dnssec: false).
- Query logging at high QPS: OFF by default; when on = sampled + async + bounded (drop).
- RPZ scope: exact + domain-suffix only; RR-based heavier policies out of hot path.

## Validated (2026-08-19)
- Unit tests pass: rpz (suffix/exact + atomic swap correctness), cache (store/get/TTL aging/id rewrite).
- Bench @1M rules: RPZ lookup ~391ns hit / ~296ns miss, 2 allocs; build 1M ~316ms (off-path).
- E2E RPZ block: 37,635 q -> all NXDOMAIN, p50 46µs / p99 194µs; counters exact.
- E2E cache hit + singleflight: 88,437 hits / 2 misses / 2 coalesced / 0 errors, p99 5.7ms.
- Miss/forward path works (throttled by public upstream RTT in sandbox). pprof endpoints live. go vet clean.

## Iteration 2 (2026-08-19) — batch/pool/prefetch/harness
- Batch UDP: recvmmsg/sendmmsg path via x/net/ipv4 ReadBatch/WriteBatch, one worker per SO_REUSEPORT socket, socket.batch + batch_size config. Validated: 119k hits, RPZ-block 43k NXDOMAIN in batch mode.
- Message pooling: internal/dnspool sync.Pool for *dns.Msg (request+response) and PackBuffer output buffers; wired into both classic and batch server paths.
- Cache prefetch: popularity + near-expiry refresh via bounded queue + background workers + singleflight (resolver.Prefetch). Unit-tested (fires for hot near-expiry, skips cold). Metric powersvx_prefetches_total.
- Competitor harness: scripts/compare.sh — one command, runs cmd/bench across scenarios x targets, samples /proc CPU+RSS, prints markdown table with QPS, p99, CPU-per-10k-queries, peak memory. Self-test: powersvx hit ~21k QPS, 0.097 cpu-s/10k, 70.7 MiB.

## Backlog / next
- P1: per-upstream health/failover + EDNS client-subnet control.
- P2: prometheus histogram (bounded buckets) for server-side latency.
- P2: optional in-process recursive mode (root hints) vs forwarding-only.
- P2: IPv6 batch path (x/net/ipv6) mirroring the ipv4 batch worker.
