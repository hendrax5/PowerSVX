# PowerSVX

Modern DNS server in Go — recursive/authoritative, encrypted transports, RPZ policy, and a React ops UI.

**Repository:** [http://x7q29vwl.servicex.id/network/powersvx](http://x7q29vwl.servicex.id/network/powersvx)

```bash
git clone http://x7q29vwl.servicex.id/network/powersvx.git
cd powersvx
```

## Features

| Area | Capabilities |
|------|----------------|
| DNS | UDP/TCP, forward/recursive, **conditional forward zones**, L1+L2 cache, PostgreSQL zones, AXFR/NOTIFY, **secondary AXFR pull** |
| Encrypted | DoT, DoH, DoH3, DoQ, DNSSEC modes, TSIG |
| Policy | RPZ (`nxdomain` / `nodata` / `pass` / **redirect** / **cname**), query ACL, rate limit, ECS, GeoDNS, views |
| Control | REST API, React UI, query logs, audit log, RBAC users, settings Save |
| Ops | Prometheus + alert rules, Grafana, analytics, ACME DNS-01, SIGHUP reload |
| Privacy | Query-log retention + IP masking |
| Intercept | MikroTik/iptables DNAT; Linux `tproxy` (`IP_TRANSPARENT`) |
| Deploy | Docker Compose, Linux systemd pack (`deploy/linux`) |

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

Copy `.env.example` → `.env` and set `PG_PASSWORD` / `API_TOKEN` before production use.

## Linux production deploy

See **[deploy/linux/README.md](deploy/linux/README.md)** for systemd install, `configs/powersvx.linux.toml`, secrets env, firewall, and a production Docker Compose override (port `53`, all services on `0.0.0.0`).

```bash
# Bare metal / VM
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-w -s' -o powersvx ./cmd/powersvx
(cd web && npm install && npm run build)
sudo ./deploy/linux/install.sh ./powersvx

# Or Docker on Linux with real DNS ports
cp .env.example .env   # set PG_PASSWORD + API_TOKEN
docker compose -f docker-compose.yml -f deploy/linux/docker-compose.linux.yml up -d --build
```

## RPZ actions

Configure feeds in **Settings → RPZ** (or TOML/`data/rpz-policies.json`):

| Action | Target | Behavior |
|--------|--------|----------|
| `nxdomain` | — | NXDOMAIN |
| `nodata` | — | NOERROR / empty answer |
| `pass` | — | Match but continue resolve |
| `redirect` | IPv4/IPv6 | Sinkhole A/AAAA to landing IP |
| `cname` | hostname | Answer CNAME to landing host |

HTTPS to blocked public sites often shows certificate errors; sinkhole landing pages work best on HTTP / captive-style internal networks.

## DNS intercept (dstnat vs TPROXY)

### MikroTik / iptables DNAT (no `tproxy` needed)

Destination is rewritten to PowerSVX — a normal listener is enough (`bind_address = "0.0.0.0"`, `udp_port`/`tcp_port` = `to-ports`).

MikroTik example (UDP; add a TCP twin if needed):

```
/ip firewall nat add chain=dstnat protocol=udp dst-address=8.8.8.8 dst-port=53 \
  action=dst-nat to-addresses=<PowerSVX-IP> to-ports=53
```

### Linux kernel TPROXY

When the packet destination stays non-local (e.g. still `8.8.8.8:53`), enable:

```toml
[server]
tproxy = true
udp_port = 53
tcp_port = 53
```

Requires Linux, `CAP_NET_ADMIN` (or root), and usually **host networking**. Example nftables sketch (adjust mark/table/if):

```
meta l4proto { udp, tcp } th dport 53 tproxy to :53 meta mark set 1 accept
```

Docker: set `tproxy = true`, add `cap_add: [NET_ADMIN]`, prefer `network_mode: host` (published `ports:` alone is not enough for real TPROXY).

## ACME

See `configs/acme.example.toml`. Enable `[acme]`, ensure the domain’s NS/public DNS reaches this PowerSVX, then **Settings → Obtain certificate** or `POST /api/v1/acme`.

## Docs

- [Production notes](docs/PRODUCTION.md)
- [Linux deploy](deploy/linux/README.md)

## License

MIT
