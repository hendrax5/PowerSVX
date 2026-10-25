# PowerSVX `v1.6.3`

Modern High-Performance DNS Server in Go & Dnsdist — recursive/authoritative, encrypted transports, RPZ & Kominfo CDB policy (>10k QPS), and React ops UI with dark/light mode.

**Repository:** [https://github.com/hendrax5/PowerSVX.git](https://github.com/hendrax5/PowerSVX.git)

---

## ⚡ Quick Install via Hermes (Langsung Cus)

Jika Anda mengelola fleet server menggunakan **Hermes** (AI Ops Assistant), Anda cukup jalankan atau perintahkan:

> *"Hermes, bootstrap/install PowerSVX di host `<nama_host_atau_ip>`"*

Hermes akan otomatis:
1. Membaca host dari `ops/inventory.local.yaml` & password dari `ops/vault.local.yaml`.
2. Melakukan SSH ke server dan clone repo ke `/home/hendra/powersvx`.
3. Menjalankan turnkey bootstrap: kernel hardening (`NOTRACK` + 3M conntrack), auto-sizing RAM, generate secret `.env`, dan menyalakan seluruh stack carrier-grade.
4. Memvalidasi port 53, Unbound `:5353`, API `:5380`, dan Grafana `:3000`.

### 🚀 Atau 1-Line Command di Terminal Server (Langsung Cus)
Cukup copy-paste perintah satu baris ini di server Ubuntu/Debian baru:

```bash
git clone https://github.com/hendrax5/PowerSVX.git /home/hendra/powersvx && cd /home/hendra/powersvx && sudo bash deploy/linux/bootstrap-node.sh
```

---

## Features

| Area | Capabilities |
|------|----------------|
| DNS Dataplane | **Dnsdist (port 53, 1M packet cache, memory-mapped CDB)** + **Unbound (127.0.0.1:5353 multi-threaded recursive backend)** |
| Performance | **>10k QPS**, kernel `NOTRACK` bypass conntrack, 3M conntrack table, 16MB socket buffers, 4096 NIC ring buffers |
| Filter & Policy | Kominfo TrustPositif (full 20M+ via AXFR/IXFR mmap), banks whitelist bypass, RPZ, query ACL, rate-limiting |
| Control & UI | PowerSVX Go `:5380`, REST API, React modular UI with **Dark & Light Mode**, query logs, RBAC |
| Observability | Auto-provisioned **Grafana (`:3000`)** embedded in `/analytics`, **Prometheus (`127.0.0.1:9091`)**, **Node-Exporter (`127.0.0.1:9101`)** |
| Encrypted DNS | DoT (`:853`), DoH/DoH3 (`:443`), DoQ (`:784`), outbound forwarders, ACME DNS-01 |
| Intercept | MikroTik / iptables DNAT; Linux kernel `tproxy` (`IP_TRANSPARENT`) |
| Automation | **Hermes** ops engine (`ops/HERMES.md`), `ops/probe.py`, auto-disk hygiene |

---

## Architecture Port Layout

| Port | Service | Access / Role |
|------|---------|---------------|
| `53` | DNS (UDP/TCP) | **Dnsdist** (Public edge, 1M packet cache + CDB mmap) |
| `5353` | Unbound Recursive | Loopback `127.0.0.1` multi-threaded backend |
| `5380` | PowerSVX Control | Web UI + REST API (AXFR initial + IXFR delta updates) |
| `3000` | Grafana Analytics | Auto-provisioned dashboards (embedded in UI `/analytics`) |
| `9091` | Prometheus Metrics | Loopback `127.0.0.1` internal metrics |
| `9101` | Node-Exporter | Loopback `127.0.0.1` host telemetry |
| `5433` | PostgreSQL | Loopback `127.0.0.1` persistent DB for logs & auth |

---

## Hermes Ops Guide (`ops/HERMES.md`)

Untuk mengelola, probe, dan update server fleet:
- **Dokumentasi Lengkap Hermes:** **[ops/HERMES.md](ops/HERMES.md)**
- **Riwayat Rilis & Update:** **[CHANGELOG.md](CHANGELOG.md)**
- **Detail Deploy Linux:** **[deploy/linux/README.md](deploy/linux/README.md)**

```bash
# Probe kesehatan seluruh fleet:
python ops/probe.py all

# Update node yang sudah berjalan ke v1.6.3:
bash deploy/linux/apply-update.sh
```

---

## Quick start (Local Development / Windows)

UDP `5353` is often taken by Edge/Copilot mDNS — use the UI config:

```powershell
cd web; npm install; npm run build; cd ..
go run ./cmd/powersvx --config configs/powersvx.ui.toml
# UI: http://127.0.0.1:5380/
.\scripts\smoke.ps1
```

## RPZ & Filter Actions

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
