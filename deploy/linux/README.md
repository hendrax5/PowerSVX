# PowerSVX — Linux deployment

Two supported paths: **systemd (bare metal/VM)** or **Docker Compose**.

## A. Systemd (recommended for DNS on port 53)

### 1. Build on a machine with Go 1.26+ and Node 22+

```bash
git clone http://x7q29vwl.servicex.id/network/powersvx.git && cd powersvx
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-w -s' -o powersvx ./cmd/powersvx
(cd web && npm install --no-audit --no-fund && npm run build)
```

Copy the tree (or release tarball) to the server, then:

```bash
sudo ./deploy/linux/install.sh ./powersvx
```

### 2. PostgreSQL

```bash
sudo -u postgres psql <<'SQL'
CREATE USER "PowerSVX" WITH PASSWORD 'same-as-PG_PASSWORD';
CREATE DATABASE "PowerSVX" OWNER "PowerSVX";
SQL
# Optional schema bootstrap:
# sudo -u postgres psql -d PowerSVX -f configs/powersvx.sql
```

Schema also auto-migrates on first start when `[database] enabled = true`.

### 3. Secrets

```bash
sudo nano /etc/powersvx/powersvx.env
# PG_PASSWORD=...
# API_TOKEN=...   # long random string
sudo chmod 600 /etc/powersvx/powersvx.env
```

### 4. Harden query ACL (before opening port 53)

Edit `/etc/powersvx/powersvx.toml`:

```toml
[acl]
allow_query = ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.1", "::1"]
```

Or set the same from UI **Settings → Query ACL** after start (admin token).

### 5. Start

```bash
sudo systemctl start powersvx
sudo systemctl status powersvx
journalctl -u powersvx -f
```

| Bind (default linux.toml) | Purpose |
|---------------------------|---------|
| `0.0.0.0:53` | DNS UDP/TCP |
| `0.0.0.0:853` | DoT |
| `0.0.0.0:443` | DoH / DoH3 |
| `0.0.0.0:784` | DoQ |
| `0.0.0.0:5380` | API + UI |
| `0.0.0.0:9100` | Prometheus metrics |

### 6. Firewall (example)

```bash
# ufw — open only what you need; API has token auth but still lock down if possible
sudo ufw allow 53/tcp
sudo ufw allow 53/udp
sudo ufw allow 853/tcp
sudo ufw allow 443/tcp
sudo ufw allow 784/udp
sudo ufw allow 5380/tcp
sudo ufw allow 9100/tcp
```

### 7. Reverse proxy for UI (optional)

Point nginx/Caddy to `http://127.0.0.1:5380` (or the host IP) with TLS. Keep `auth_type = "token"`.

### 8. Reload runtime settings

```bash
sudo systemctl reload powersvx   # SIGHUP: runtime-settings.json + plugins
```

### Layout

| Path | Role |
|------|------|
| `/usr/local/bin/powersvx` | Binary |
| `/etc/powersvx/powersvx.toml` | Main config |
| `/etc/powersvx/powersvx.env` | Secrets (`PG_PASSWORD`, `API_TOKEN`) |
| `/etc/powersvx/certs/` | TLS for DoT/DoH |
| `/var/lib/powersvx/` | `--data-dir` (cache, DNSSEC, RPZ, runtime-settings) |
| `/usr/share/PowerSVX/web` | Built UI |

### TPROXY note

If using kernel TPROXY, set `tproxy = true`, add `CAP_NET_ADMIN` to the unit’s `AmbientCapabilities` / `CapabilityBoundingSet`, and use host routing/nftables. See root `README.md`.

---

## B. Docker Compose on Linux

Use host ports `53` directly (stop systemd-resolved conflict first if needed):

```bash
# /etc/docker compose override example — map 53:53
# Or edit docker-compose.yml ports to "53:53/udp" and "53:53/tcp"

cp .env.example .env
# set strong PG_PASSWORD and API_TOKEN
docker compose up -d --build
```

For production Docker, prefer `configs/powersvx.docker.toml` plus a `.env` with strong secrets. Ports publish on **0.0.0.0**. Prometheus is on host **9091** (maps to container 9090) because host 9090 is often already in use. Restrict `[acl] allow_query` and firewall unused ports.

| Host port | Service |
|-----------|---------|
| 53 | DNS |
| 853 / 443 / 784 | DoT / DoH / DoQ |
| 5380 | API + UI |
| 9100 | App metrics |
| 9091 | Prometheus UI |
| 3000 | Grafana |
| 5433 | Postgres |

### Host networking (real client IPs / VPS)

Published ports SNAT client IPs to the Docker bridge (`172.x`), which breaks ACL and rate-limit by source. On a dedicated DNS VPS use:

```bash
# DB must be reachable on the host loopback publish:
#   configs/powersvx.docker.toml → host = "127.0.0.1", port = 5433
docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml up -d --build
```

Do **not** overwrite a host-network deploy with the default bridge `docker-compose.yml` alone — that drops `network_mode: host` and PowerSVX will fail to reach Postgres at `127.0.0.1:5433`.

Analytics UI (`/analytics`) embeds Grafana (`:3000`, board `powersvx-dns`). Prometheus scrapes via job `powersvx-host` → `host.docker.internal:9100`.

Conflict with `systemd-resolved` on port 53:

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
echo -e '[Resolve]\nDNSStubListener=no' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
sudo systemctl restart systemd-resolved
# confirm host :53 is free
ss -ulnp | grep ':53' || echo 'udp/53 free'
ss -tlnp | grep ':53' || echo 'tcp/53 free'
```

### PowerSVX / Grafana crash-loop

```bash
docker logs powersvx --tail 80
docker logs powersvx-grafana --tail 40
```

Common causes:
- **Empty `./certs` mount** hides image TLS certs — do not mount `./certs` until you have real `fullchain.pem` + `privkey.pem`
- **Host port 53 busy** (`systemd-resolved`) — free it with the steps above
- **Grafana bind-mount permissions** — compose now uses named volume `grafana-data`

Recreate cleanly:

```bash
git pull origin main
docker compose -f docker-compose.yml -f deploy/linux/docker-compose.linux.yml up -d --build --force-recreate
docker ps
ss -ulnp | grep ':53'
dig @127.0.0.1 example.com
```

### Build fails on `apk add` / Alpine CDN

PowerSVX images use **Debian bookworm** (not Alpine) so builds do not depend on `dl-cdn.alpinelinux.org`. Compose also sets `build.network: host` to avoid flaky Docker-bridge DNS.

```bash
git pull origin main
docker compose build --no-cache powersvx
docker compose -f docker-compose.yml -f deploy/linux/docker-compose.linux.yml up -d
```

If `apt-get` still fails, check host egress/DNS, then retry with an explicit host-network build:

```bash
docker build --network=host -t powersvx-powersvx .
```

Fallback without Docker image builds: use the **systemd** path in section A (compile binary on a machine that can reach `proxy.golang.org` / `registry.npmjs.org`).

---

## Checklist before go-live

- [ ] Strong `API_TOKEN` / `PG_PASSWORD`
- [ ] `[acl] allow_query` set for your networks
- [ ] Real TLS certs (or ACME) replacing install.sh self-signed
- [ ] Postgres backups
- [ ] Firewall limits who can reach UI/metrics/DB
- [ ] UI/API protected (`API_TOKEN` / admin password)
- [ ] `systemctl status powersvx` healthy; `dig @127.0.0.1 example.com` works
