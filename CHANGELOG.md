# Changelog

All notable changes to the PowerSVX project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed
- The default host configuration no longer makes Unbound forward every query to itself (ticket #40): `[resolver] mode = "recursive"`, no forwarders. The Control Plane never writes a forwarder that points at Unbound's own listener or at dnsdist, logs a warning and reports it in the health output. `bootstrap-node.sh` and `apply-update.sh` validate the Unbound configuration (`deploy/linux/check-unbound-conf.sh`) before touching Unbound. `dns-ready.sh -r` checks recursion with a real name and is used by the dnsdist healthcheck, `bootstrap-node.sh` and `apply-update.sh`. A failed Unbound reload is logged as an error and shown in the health output. The sample `configs/unbound/unbound.conf` enables the control interface like the generator. Operators of existing nodes: see docs/PRODUCTION.md, "Unbound forwards to itself".

---

## [1.7.1] - 2026-11-17

### Added
- **Docker CD Pipeline (`.github/workflows/release.yml`)**:
  - Automatic multi-arch (`linux/amd64`, `linux/arm64`) image build & push to `ghcr.io/hendrax5/powersvx` gated on passing tests (`:latest`, `:<version>`, `:<major>.<minor>` on `v*` tags; `:edge` on `main`).
  - Automatic GitHub Release creation on `v*` tags attaching standalone `powersvx-linux-amd64`, `powersvx-linux-arm64`, `web-dist.tgz`, and `SHA256SUMS.txt` (`make_latest: false` preserves `filter-seed` asset URLs).
  - Multi-arch native cross-compilation support in [`Dockerfile`](Dockerfile) using `$BUILDPLATFORM` + `$TARGETOS`/`$TARGETARCH`.
- **Scheduled Auto-Update via Watchtower (`docker-compose.yml`)**:
  - Added `nickfedor/watchtower:latest` (`powersvx-watchtower`, Docker Engine API ≥ 1.44 compatible) with `WATCHTOWER_LABEL_ENABLE=true`, `WATCHTOWER_CLEANUP=true`, and `WATCHTOWER_SCHEDULE=0 15 3 * * *` (`TZ=Asia/Jakarta`, 03:15 WIB daily).
  - Scoped exclusively to the `powersvx` control-plane container (`com.centurylinklabs.watchtower.enable=true`) so `dnsdist`, `Unbound`, and `Postgres` are never auto-restarted.
  - Updated [`deploy/linux/bootstrap-node.sh`](deploy/linux/bootstrap-node.sh) (pull-first with build fallback) and [`deploy/linux/apply-update.sh`](deploy/linux/apply-update.sh) (`POWERSVX_PULL_IMAGE=1` option + Watchtower lifecycle).

### Fixed
- Pinned `config.DefaultFilterSeedURL` directly to `/releases/download/filter-seed/blocklist-seed.tgz` so app releases never break first-boot filter seed downloads.
- Fixed test alignment in `internal/api/cdb_sync_test.go`, `internal/rpz/axfr_test.go`, `internal/server/update_test.go`, and skipped self-bumping SOA serial on `TypeSOA` insertion in `internal/authoritative/store.go`.

---

## [1.7.0] - 2026-11-17

### Added
- **Carrier-Grade Slave Authoritative Zones (`internal/secondary`)**:
  - Full **RFC 1995 IXFR** incremental zone transfer with automatic **AXFR** fallback when primary masters reject or do not support IXFR.
  - Pre-transfer **SOA serial check** using **RFC 1982** wrap-around serial arithmetic (`internal/tsig.SerialGreater`), skipping unchanged transfers.
  - Automatic honoring of upstream master SOA **`Refresh` / `Retry` / `Expire`** timers (with optional `refresh_seconds` override) and `inFlight` transfer deduplication.
  - Optional outbound **RFC 2845 TSIG** authentication (`tsig_key`) across SOA, IXFR, and AXFR pulls (`internal/tsig`).
  - Atomic per-zone record persistence (`data/secondary-zones/*.json`) restored automatically on boot so slave zones serve offline even before masters respond.
  - Automatic dataplane sync callback (`SyncSecondaryDataplane`) updating `authzones.cdb`, `dnsdist`, and Unbound `auth_zones`.
  - Full Web UI management via **Settings → Tools → AXFR → Secondary Authoritative Zones** (`SecondaryZonesPanel`) and `[SLAVE]` zone badges/warnings in **Domains** (`DomainsPage.jsx`).
- **Carrier-Grade Slave Filter Feeds (`internal/rpz`, `internal/api/cdb_sync.go`)**:
  - Per-policy feed cache files (`data/blocklist/feeds/<policy>-<hash>.txt` + `manifest.txt`) preventing multi-policy overwrites when a feed skips on unchanged SOA or triggers on targeted `NOTIFY`.
  - Memory-efficient streaming AXFR (`StreamAXFRNames`), optional outbound `tsig_key` support on `format="axfr"` feeds, and winning `Master` tracking.
  - Seamless seed-to-IXFR handoff fallbacks: `blockcdb.ReadSeedManifest` (serial recovery from `seed-manifest.json`) and `blockcdb.ReadCDBKeys` (baseline extraction directly from `domains.cdb`).
- **ISP DNS Core & Security Suite**:
  - Full control-plane → dataplane sync (`dnsdistctl` dynamic ACL/RRL/CDB reload + Unbound runtime config drop-in for forwarders, DNSSEC, ECS, and `auth_zones`).
  - Multi-algorithm DNSSEC zone signing (`ECDSAP256SHA256`, `ED25519`, `ECDSAP384SHA384`, `RSASHA256`) + **NSEC3** support, BIND zone import/export, and SOA timer editing.
  - Live DNS query ring-buffer + SSE stream (`/api/v1/stream`), Cache Explorer (`web/src/features/cache`), Security & Dynamic IP Bans (`internal/aclban`, `web/src/features/security`), DNS Client Lookup + Iterative Root Trace (`internal/api/tools.go`), Scoped SHA-256 API tokens (`internal/apiauth/tokens.go`), and Web UI EN/ID switcher (`web/src/i18n.jsx`).

### Fixed
- **Dataplane `NOTIFY` Routing (`deploy/linux/gen-dnsdist-conf.sh`, `internal/server`)**: Routed `OpcodeRule(DNSOpcode.Notify)` directly to PowerSVX (`:5354`) ahead of blocklist/cache rules, and enforced master source IP or valid TSIG verification on inbound `HandleNotifyFrom` and `HandleRPZNotify` (`REFUSED` on unauthorized senders).
- **Code Review Hardening**: Resolved resource leaks and safety issues across PTY terminal lifecycle, conntrack/tproxy parsing, anomaly/bloom/cache locking, database context deadlines, host network interface validation (`internal/hostnet`), and RFC 1982 wraparound serial checks on outbound XFER.

---

## [1.6.3] - 2026-10-25

### Added
- **Turnkey One-Shot Node Bootstrap (`deploy/linux/bootstrap-node.sh`)**:
  - Automatically installs Docker Engine and compose plugin if missing.
  - Resolves host port 53 conflicts (disables `systemd-resolved` stub listener).
  - Dynamically sizes Unbound (`127.0.0.1:5353`) and Dnsdist (`0.0.0.0:53`) configurations to host RAM and CPU cores.
  - Auto-generates secure cryptographic secrets in `.env` (`PG_PASSWORD`, `API_TOKEN`, `GRAFANA_PASSWORD`, `DNSDIST_KEY`).
  - Launches full carrier-grade stack in Docker Host mode (dnsdist, unbound, powersvx, postgres, prometheus, node-exporter, grafana).
- **Hermes Fleet Automation (`ops/HERMES.md`)**:
  - Documented one-shot bootstrap for brand-new nodes via inventory.
  - Automated update workflow with `apply-update.sh` and build cache pruning.
- **Kernel & Network Stack Hardening for >10k QPS (`deploy/linux/os-hardening.sh`)**:
  - `iptables NOTRACK` on UDP port 53: bypasses conntrack state tables to eliminate CPU overhead and prevent packet drops for heavy NAT multi-user traffic.
  - Expanded conntrack table to 3,000,000 entries (`nf_conntrack_max = 3000000`, 750,000 buckets).
  - Expanded socket buffers to 16 MB (`net.core.rmem_max = 16777216`, `wmem_max = 16777216`).
  - Maximized network card (NIC) hardware ring buffers to 4096 via `ethtool`.
- **UI Dark & Light Mode**:
  - Centralized `ThemeProvider` and `useTheme` hook with system theme detection (`prefers-color-scheme`) and `localStorage` persistence.
  - Semantic CSS design tokens in `web/src/index.css` supporting `:root, [data-theme="dark"]` and `[data-theme="light"]`.
  - Added instant theme toggles in `Shell.jsx` header and `LoginPage.jsx`.
- **Auto-Provisioned Grafana Analytics**:
  - Auto-mounted datasource and dashboard (`powersvx-dns`) in Grafana on port 3000.
  - Seamlessly embedded in PowerSVX Web UI under `/analytics`.

### Changed
- **Frontend Architecture Modularization**:
  - Refactored monolithic `App.jsx` (~3,950 lines) down to 138 lines.
  - Extracted domain features into dedicated modules under `web/src/features/` (`auth`, `dashboard`, `domains`, `lookup`, `analytics`, `audit`, `settings`).
  - Implemented route-based lazy loading with `React.lazy()` and `<Suspense>` for isolated chunk bundles.
- **Default Installer (`deploy/linux/install.sh`)**:
  - Defaults directly to full high-performance production stack (`bootstrap-node.sh`), with `--standalone` option for minimalist single-binary lab environments.
- **Dnsdist Dataplane Optimizations**:
  - Expanded packet cache to 1,000,000 entries.
  - Increased backend sockets to 64 parallel threads to Unbound.

### Fixed
- **DNS Leak Prevention**:
  - Patched non-A/AAAA queries (Type 65 HTTPS, MX, TXT) on blocked CDB domains to return `NODATA (NOERROR)`, preventing upstream leaks and avoiding browser retry storms.
- **Backend API Security**:
  - Patched CORS Reflection vulnerability (CWE-942) in `internal/api/api.go` with strict origin matching.
  - Injected security headers on all API responses (`X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`).
- **Internal Metrics Exposure**:
  - Bound Prometheus (`:9091`) and Node-Exporter (`:9101`) to `127.0.0.1` loopback only.
- **Dependency Vulnerabilities**:
  - Resolved all npm audit vulnerabilities in `web/` (0 vulnerabilities reported).

---

## [1.6.2] - 2026-10-24
- Spread dnsdist backend queries across all Unbound threads.
- Enforce allow_query/deny_query on dnsdist and make IPv6 listen optional.
- Resolve PTR normally and rate-limit per-client PTR in dnsdist.

## [1.6.1] - 2026-10-20
- Fix host forwarders to Unbound :5353 and prune Docker after updates.
- Default TrustPositif AXFR with GitHub CDB seed and resilient filter sync.
- Skip unchanged SOA and prefer IXFR for dnsdist CDB refreshes.

## [1.6.0] - 2026-08-19
- Ship dnsdist+CDB dataplane with control-plane UI and host metrics.
- Absorb NXDOMAIN floods with RFC 8198 NSEC cache and skip dead forwarders.
- Show release v1.6.0 plus git sha in the UI.
