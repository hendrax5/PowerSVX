# PowerSVX

Modern DNS server in Go — **Phase 1–4** (foundation → encrypted DNS → security/routing → REST + Web UI).

## Features

| Phase | Capabilities |
|-------|----------------|
| 1 | UDP/TCP, forward/recursive, L1+L2 cache, PostgreSQL zones |
| 2 | DoT, DoH, **DoQ**, DNSSEC opportunistic/validate, TSIG key store |
| 3 | RPZ, rate limit, **ECS**, **GeoDNS**, **Split Horizon**, Prometheus |
| 4 | REST API (zones/records/settings/lookup), React Web UI on `:5380`, **live error log** (SSE) |

Deferred: Raft/gRPC cluster, DoH3, ACME, full 20M RPZ radix, live query stream (intentionally omitted — use metrics instead).

## Quick start

```bash
go mod tidy
cd web && npm install && npm run build && cd ..
go run ./cmd/gencert ./certs   # for DoT/DoH/DoQ
go run ./cmd/powersvx --config configs/powersvx.toml
go run ./cmd/dnsquery 127.0.0.1:5353 example.com A
```

Open the UI: [http://127.0.0.1:5380/](http://127.0.0.1:5380/)

Encrypted (after enabling `[server.tls]`):

```bash
go run ./cmd/dohquery https://127.0.0.1:8443/dns-query example.com A
go run ./cmd/dotquery 127.0.0.1:8853 example.com A
go run ./cmd/doqquery 127.0.0.1:784 example.com A
```

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
| 5380 | REST API + Web UI |
| 9100 | Prometheus |
| 5432 | Postgres |

## Config highlights

```toml
[api]
rest_enabled = true
rest_bind = "0.0.0.0:5380"
# auth_type = "token"
# api_token = "changeme"

[rate_limit]
enabled = true

[rpz]
enabled = true
policies = [{ name = "sample", source = "./configs/sample-blocklist.txt", action = "nxdomain" }]

[geodns]
enabled = true
overrides = [{ ip = "127.0.0.1", country = "ID", tag = "ID" }]

[split_horizon]
enabled = true
views = [{ name = "internal", networks = ["10.0.0.0/8", "192.168.0.0/16"] }]
```

Optional MaxMind DB: set `geodns.database_path` to `GeoLite2-City.mmdb`.

## License

MIT
