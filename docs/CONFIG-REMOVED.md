# Configuration keys removed in version 2

Version 2 (ADR-0001) makes dnsdist the only Dataplane. The Go Control Plane no longer
resolves, caches or filters customer queries, so the keys below have no meaning.

A configuration file that still sets them loads normally. The Control Plane ignores each
key and logs one warning at start: `config key ignored since version 2` with the key name.
Delete the keys when convenient; nothing reads them.

| Key | Was for | Now |
|---|---|---|
| `[cache]` (every key: `type`, `path`, `max_size_mb`, `ttl_seconds`, `min_ttl`, `negative_ttl`, `serve_stale`, `stale_ttl`, `prefetch_pct`) | Go two-tier answer cache | dnsdist and Unbound cache; tune them in their own configuration |
| `server.dot_port`, `server.doh_port`, `server.doq_port` | Go DoT, DoH and DoQ listeners | dnsdist terminates encrypted transports |
| `[server.tls]` (`enabled`, `cert_file`, `key_file`) | certificate for those listeners | dnsdist reads its own certificate; ACME settings stay under `[acme]` |
| `resolver.root_hints_file`, `resolver.qname_minimization`, `resolver.timeout_ms`, `resolver.fallback_timeout_ms`, `resolver.max_inflight` | Go recursive resolver | Unbound |
| `resolver.ecs_prefix_v4`, `resolver.ecs_prefix_v6` | ECS prefix of the Go resolver | dnsdist |
| `logging.query_log_destination` | where the Go handler wrote query logs | the Observability Profile reads dnsdist |
| `rpz.hot_cache_max`, `rpz.hot_seed_top_n` | in-process Filter hot cache | the Filter is the dnsdist CDB |

Still read: `resolver.forwarders`, `resolver.dnssec_*`, `resolver.edns_buffer_size`,
`resolver.forward_zones`, `[acl]`, `[rate_limit]`, `[rpz]` feeds, `[api]`, `[logging]`
(level, format, retention), `[acme]`, `[database]`, `[metrics]`.
