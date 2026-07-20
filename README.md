# PowerSVX

Modern DNS server in Go — **Phase 1–3** (foundation + encrypted DNS + RPZ/rate limit).

## Features

| Phase | Capabilities |
|-------|----------------|
| 1 | UDP/TCP, forward/recursive, L1+L2 cache, PostgreSQL zones |
| 2 | DoT, DoH, **DoQ**, DNSSEC opportunistic/validate, TSIG key store |
| 3 | **RPZ/blocklist**, **rate limit**, Prometheus `:9100` |

Deferred: DoH3, GeoDNS, ECS, Split Horizon views, Raft, React UI, ACME.

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

[metrics]
prometheus_enabled = true
prometheus_bind = "0.0.0.0:9100"
```

## License

MIT
