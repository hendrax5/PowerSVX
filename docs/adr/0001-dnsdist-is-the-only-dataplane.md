---
status: accepted
---

# dnsdist + Unbound is the only dataplane; the Go query path is removed

PowerSVX set out to be a single Go binary that answers DNS itself (`PowerSVX_Architecture.md`), and later grew three selectable dataplanes: Go on `:53`, Unbound on `:53`, and dnsdist on `:53` with Unbound behind it. The goal is now to serve more queries per core and per megabyte than Technitium. We keep only dnsdist + Unbound and delete the Go recursive path (resolver, L1/L2 cache, in-process RPZ engine, Go DoH/DoQ/TPROXY listeners) and the Unbound-on-`:53` mode. The Go process remains as the control plane and as the authoritative backend that dnsdist forwards zone traffic to.

## Considered Options

- **Optimise the Go query path.** Rejected: an audit found about eight global mutexes, a goroutine and full message unpack per packet, and synchronous disk I/O on cache misses, plus three correctness bugs in the cache (TTLs not decremented, EDNS cookies shared across clients, hash-only cache keys). Reaching dnsdist's throughput means rewriting packet I/O, the cache and all per-query accounting.
- **Keep all three modes.** Rejected: each mode has its own filter sync path, so every filter change and every benchmark has to be done three times, and only one mode runs in production.

## Consequences

- PowerSVX is no longer a single binary. Answering DNS on a development machine needs dnsdist and Unbound, in practice through Docker.
- DoQ must be served by dnsdist before the Go listener is deleted.
- `PowerSVX_Architecture.md` describes the superseded design.
