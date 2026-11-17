# PowerSVX — Linux Deployment

## A. Turnkey Full Production Stack (>10k QPS, Recommended)

Deploys the complete carrier-grade stack with **zero manual configuration**:
* **Public DNS (:53)**: `dnsdist` with 1M packet cache + memory-mapped CDB blocklist (Kominfo 20M+ rules)
* **Backend Resolver (:5353)**: `Unbound` multi-threaded recursive engine on loopback
* **Control-Plane (:5380)**: `PowerSVX` Web UI & REST API (AXFR initial + IXFR incremental auto-sync)
* **Observability Stack**: `Grafana` (:3000, auto-embedded in UI) + `Prometheus` (:9091) + `Node-Exporter` (:9101)
* **Automatic Hardening**: Conntrack 3M limits, 16MB socket buffers, and `NOTRACK` for zero packet drops.

### Quick Start (1 Command on Clean Server)

```bash
git clone https://github.com/hendrax5/PowerSVX.git /home/hendra/powersvx
cd /home/hendra/powersvx
sudo bash deploy/linux/bootstrap-node.sh
```

---

## B. Standalone Systemd (Bare-metal Binary Only)
For lab, testing, or minimalist single-binary deployments:

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

**Default for a DNS VPS: host networking.** Bridge/`ports:` publish SNAT client IPs to the Docker gateway (`172.18.0.1`), so ACL, rate-limit, and query logs look wrong (almost all traffic from one IP).

Stop host conflicts on `:53` first if needed (e.g. `systemd-resolved`), then:

```bash
cp .env.example .env
# set strong PG_PASSWORD, API_TOKEN, ADMIN_PASSWORD
docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml up -d --build
```

This override sets `network_mode: host` and mounts `configs/powersvx.docker.host.toml` (Postgres via `127.0.0.1:5433`). Prometheus is on host **9091** (container 9090). Restrict `[acl] allow_query` and firewall unused ports.

It also starts **Unbound on `127.0.0.1:5353`** as the default recursive backend (`mode=forward` in the host TOML). Conditional forward zones still override per domain. Details: [docs/UNBOUND-HYBRID.md](../../docs/UNBOUND-HYBRID.md).

| Host port | Service |
|-----------|---------|
| 53 | DNS (PowerSVX) |
| 127.0.0.1:5353 | Unbound recursive (loopback only) |
| 853 / 443 / 784 | DoT / DoH / DoQ |
| 5380 | API + UI |
| 9100 | App metrics |
| 9091 | Prometheus UI |
| 3000 | Grafana |
| 5433 | Postgres (loopback publish in host override) |

Do **not** overwrite a host-network deploy with plain `docker compose up` / bridge-only `docker-compose.yml` — that drops `network_mode: host` and client IPs become `172.x` again.

### Bridge networking (dev / avoid if possible)

Only for local lab where host `:53` must stay free. Prefer mapped ports in root `docker-compose.yml` (e.g. `5453→53`).

Default Docker **published UDP ports** use `docker-proxy` (userland). Under high DNS QPS that process can eat **multiple GB RAM and tens of % CPU** (seen ~4 GB on :53 alone). Options if you must stay on bridge:

1. **Disable userland proxy (recommended for bridge)** — iptables/nft DNAT only, no `docker-proxy` process:

```bash
# /etc/docker/daemon.json
{
  "userland-proxy": false
}
sudo systemctl restart docker
# then recreate the stack
```

2. Prefer switching to **host networking** (section above) instead of staying on bridge.

3. **macvlan / ipvlan** — container gets its own L2/L3 address; more ops complexity.

4. Avoid publishing UDP 53 through bridge at all if another host DNS forwards to the container’s **private IP** on the compose network (no host port map).

Analytics UI (`/analytics`) embeds Grafana (`:3000`, board `powersvx-dns`). Prometheus scrapes via job `powersvx-host` → `host.docker.internal:9100`.

### Disk guard (keep usage under ~80%)

Query logs + Docker logs fill disks quickly and can crash Postgres. Install the hourly guard:

```bash
cd /home/hendra/powersvx   # your clone path
sudo install -m 755 deploy/linux/disk-guard.sh /usr/local/sbin/powersvx-disk-guard
echo "POWERSVX_DIR=$(pwd)" | sudo tee /etc/default/powersvx-disk-guard
echo '15 * * * * root . /etc/default/powersvx-disk-guard; /usr/local/sbin/powersvx-disk-guard' | sudo tee /etc/cron.d/powersvx-disk-guard
# dry-run now:
sudo POWERSVX_DIR=$(pwd) /usr/local/sbin/powersvx-disk-guard || true
df -h /
```

Also: Docker compose caps container logs at 50MB×3, and `query_log_retention_days = 7` in `powersvx.docker.toml`.

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

### Auto-Update (Docker CD via GHCR + Watchtower)

Release tags (`v*`) automatically publish multi-arch images to `ghcr.io/hendrax5/powersvx:latest`.
The compose stack includes `powersvx-watchtower` (`nickfedor/watchtower:latest`), scoped via `WATCHTOWER_LABEL_ENABLE=true` **only** to the `powersvx` control-plane container (`dnsdist`, `unbound`, and `postgres` are never restarted automatically), scheduled at **03:15 WIB** (`WATCHTOWER_SCHEDULE=0 15 3 * * *`).

Manual pull or local build anytime:

```bash
# Pull prebuilt image from GHCR (fastest):
POWERSVX_PULL_IMAGE=1 bash deploy/linux/apply-update.sh

# Or build locally from git checkout:
git pull origin main
bash deploy/linux/apply-update.sh
docker ps
ss -ulnp | grep ':53'
dig @127.0.0.1 example.com
```

### Build fails on `apk add` / Alpine CDN

PowerSVX images use **Debian bookworm** (not Alpine) so builds do not depend on `dl-cdn.alpinelinux.org`. Compose also sets `build.network: host` to avoid flaky Docker-bridge DNS.

```bash
git pull origin main
docker compose build --no-cache powersvx
docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml up -d
```

If `apt-get` still fails, check host egress/DNS, then retry with an explicit host-network build:

```bash
docker build --network=host -t powersvx-powersvx .
```

Fallback without Docker image builds: use the **systemd** path in section A (compile binary on a machine that can reach `proxy.golang.org` / `registry.npmjs.org`).

---

## Checklist before go-live

- [ ] Docker uses **host** compose: `-f deploy/linux/docker-compose.host.yml` (not bridge-only)
- [ ] Strong `API_TOKEN` / `PG_PASSWORD`
- [ ] `[acl] allow_query` set for your networks
- [ ] Real TLS certs (or ACME) replacing install.sh self-signed
- [ ] Postgres backups
- [ ] Firewall limits who can reach UI/metrics/DB
- [ ] UI/API protected (`API_TOKEN` / admin password)
- [ ] `systemctl status powersvx` or `docker ps` healthy; `dig @127.0.0.1 example.com` works
- [ ] Query logs show real client IPs (not `172.18.0.1`)
