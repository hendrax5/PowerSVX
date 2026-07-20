# PowerSVX

Modern DNS server in Go — Phase 1–4 + ops extras (ACME, Grafana, analytics).

## Features

| Area | Capabilities |
|------|----------------|
| DNS | UDP/TCP, forward/recursive, L1+L2 cache, PostgreSQL zones |
| Encrypted | DoT, DoH, DoQ, DNSSEC modes, TSIG |
| Policy | RPZ, rate limit, ECS, GeoDNS, split horizon |
| Control | REST API, React UI, live **error** log, settings Save |
| Ops | Prometheus, Grafana dashboards, aggregate analytics, ACME DNS-01 |

## Quick start (Windows)

UDP `5353` is often taken by Edge/Copilot mDNS — use the UI config:

```powershell
cd web; npm install; npm run build; cd ..
go run ./cmd/powersvx --config configs/powersvx.ui.toml
# UI: http://127.0.0.1:5380/
.\scripts\smoke.ps1
```

## Docker

```bash
docker compose up -d --build
```

| Host | Service |
|------|---------|
| 5453 | DNS |
| 5380 | API + UI |
| 9100 | Prometheus metrics (app) |
| 9090 | Prometheus server |
| 3000 | Grafana (admin/admin by default) |

## ACME

See `configs/acme.example.toml`. Enable `[acme]`, ensure the domain’s NS/public DNS reaches this PowerSVX, then **Settings → Obtain certificate** or `POST /api/v1/acme`.

## License

MIT
