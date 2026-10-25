# Changelog

All notable changes to the PowerSVX project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
