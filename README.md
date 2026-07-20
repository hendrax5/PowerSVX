# PowerSVX

Modern DNS server in Go — **Phase 1–3** (foundation + encrypted DNS + RPZ/rate limit).

## Features

| Phase | Capabilities |
|-------|----------------|
| 1 | UDP/TCP, forward/recursive, L1+L2 cache, PostgreSQL zones |
| 2 | DoT, DoH, **DoQ**, DNSSEC opportunistic/validate, TSIG key store |
| 3 | RPZ, rate limit, **ECS**, **GeoDNS**, **Split Horizon**, Prometheus |

Deferred: DoH3, Raft, React UI, ACME, full 20M RPZ radix.

## Quick start

```bash
go mod tidy
go run ./cmd/gencert ./certs   # for DoT/DoH/DoQ
go run ./cmd/powersvx --config configs/powersvx.toml
go run ./cmd/dnsquery 127.0.0.1:5353 example.com A
go run ./cmd/dnsquery 127.0.0.1:5353 blocked.test A   # NXDOMAIN via RPZ sample
```

Encrypted (after enabling `[server.tls]`):

```bash
go run ./cmd/dohquery https://127.0.0.1:8443/dns-query example.com A
go run ./cmd/dotquery 127.0.0.1:8853 example.com A
go run ./cmd/doqquery 127.0.0.1:784 example.com A
```

Browser DoH convenience: `https://127.0.0.1:8443/dns-query?name=example.com&type=A`

## Docker

```bash
docker compose up -d --build
```

| Host | Service |
|------|---------|
| 5453 | DNS UDP/TCP |
| 8853 | DoT |
| 8443 | DoH |
| 784 | DoQ |
| 5380 | REST API |
| 9100 | Prometheus |
| 5432 | Postgres |

## Config highlights

```toml
[rate_limit]
enabled = true
default_qps = 100

[rpz]
enabled = true
policies = [{ name = "sample", source = "./configs/sample-blocklist.txt", action = "nxdomain" }]

[geodns]
enabled = true
default_tag = "default"
overrides = [{ ip = "127.0.0.1", country = "ID", tag = "ID" }]

[split_horizon]
enabled = true
views = [{ name = "internal", networks = ["10.0.0.0/8", "192.168.0.0/16"] }]

[resolver]
ecs_enabled = true
```

Optional MaxMind DB: set `geodns.database_path` to `GeoLite2-City.mmdb`. Without it, overrides + default tag still work.

## License

MIT
