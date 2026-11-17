# PowerSVX production notes (Raft clustering deferred)

## DNS dataplane (dnsdist+CDB) vs control-plane (PowerSVX)

On production hosts (`POWERSVX_DNS_DATAPLANE=dnsdist`, default):

| Role | Process | Ports |
|------|---------|-------|
| Public DNS + CDB blocklist + bank whitelist | **dnsdist** | `:53` |
| Recurse-only backend | **Unbound** | `127.0.0.1:5353` |
| UI / API / AXFR→CDB sync / Kominfo outbound AXFR | **PowerSVX** | `:5380`, auth/AXFR `:5354` |

- Komdigi AXFR / hosts feeds → per-policy feed caches (`data/blocklist/feeds/`) merged into `data/blocklist/domains.cdb` (full list, mmap; no Unbound 1.5M RPZ cap). Banks filtered from CDB + dnsdist `SuffixMatchNode`.
- **CDB refresh:** RFC 1982 serial comparison on SOA check first (skip unchanged policies while preserving their entries in the merged CDB); if serial advanced, stream AXFR or apply incremental **IXFR** delta with automatic AXFR fallback. Serials in `data/rpz-axfr-state.json` (same file as Unbound RPZ path). `dnsdist` forwards `OpcodeNotify` directly to PowerSVX (`:5354`).
- Spoof blocked A → `139.255.196.196` (Komdigi sinkhole). Regen conf: `deploy/linux/gen-dnsdist-conf.sh`.
- **Do not put Go PowerSVX back on public `:53`.** See `ops/HERMES.md`.

### Legacy: Unbound RPZ on `:53`

Set `POWERSVX_DNS_DATAPLANE=unbound` and stop dnsdist. Partial TrustPositif: `POWERSVX_RPZ_MAX_ENTRIES` auto-cap on small RAM. Full Unbound RPZ needs **≥16 GiB**. Keep `POWERSVX_UNBOUND_QUERYLOG=0`. Run `deploy/linux/unbound-rpz-guard.sh` before Unbound recreate.

## Query ACL
- `[acl] allow_query` — CIDRs/IPs allowed to query DNS. **Empty = allow all.**
- `[acl] deny_query` — always refused (wins over allow).
- Editable in UI Settings (no restart). Denied clients get REFUSED.
- Separate from `[transfer] allow_from` (AXFR only) and rate-limit `whitelist` (rate-limit bypass only).

## Auth / RBAC
- Modes: `auth_type = "none"` | `"token"` | `"local"` (hybrid UI login + API tokens).
- **Local (recommended for UI):** `auth_type = "local"`. Bootstrap first admin with env `ADMIN_PASSWORD` (creates `admin` in `data/users.json`). Or set `[[api.users]]` with bcrypt `password_hash`.
- UI: `/login` (username/password only). Session cookie `powersvx_session` (HttpOnly, 12h).
- **API automation:** scripts still use `Authorization: Bearer <token>` via `api_token` / `[[api.tokens]]` (not via the login form).
- Roles: `admin` (full), `operator` (zones/RPZ ok; no settings write / backup restore / user mgmt), `readonly` (GET only).
- Health (`/api/v1/health`) stays open. Login rate-limited (~5/min/IP).
- `GET /api/v1/audit` returns recent control-plane audit events.
- Process refuses to start if `token` with no tokens, or `local` with no users and no `ADMIN_PASSWORD`.
- SSO/OIDC deferred.

## Zone transfer
- `[transfer] allow_axfr = true` enables outbound zone transfer (`OpcodeNotify` is routed by `dnsdist` straight to PowerSVX `:5354`).
- **Outbound IXFR is answered as full AXFR** (RFC 1982 serial check; clients up-to-date get current SOA only).
- **Secondary (slave) authoritative zones:** configure via API (`/api/v1/secondary`) or **Settings → Tools → AXFR → Secondary Zones** (`data/secondary-zones.json` + persisted zone records in `data/secondary-zones/*.json`). Supports SOA serial pre-check (RFC 1982), true RFC 1995 incremental **IXFR** with automatic AXFR fallback, upstream SOA `Refresh`/`Retry`/`Expire` scheduling, optional RFC 2845 **TSIG** signing (`tsig_key`), source-IP/TSIG-verified inbound DNS `NOTIFY`, and automatic `authzones.cdb` / Unbound / `dnsdist` dataplane sync.
- `require_tsig = true` (default) needs a valid TSIG on inbound transfer requests.
- `allow_from` CIDR ACL; `notify` lists secondaries for DNS NOTIFY after zone create.

## Dynamic DNS (RFC 2136)
- `[update] enabled = true` accepts OpcodeUpdate for zones already in the auth store.
- `require_tsig` (default true) + `[tsig]` keys; optional `allow_from` CIDRs.
- Optional `[[update.policies]]` map TSIG `key` → `zones` (empty zones = all).
- Prerequisites: name/RRset existence (ANY/NONE) and exact RR match (IN).
- Updates: add (IN), delete RRset (ANY), delete exact RR (NONE). SOA serial bumps; secondaries are NOTIFYed.

## Conditional forwarders
- Default resolver mode is **recursive**. Global `[resolver] forwarders` plus optional `[[resolver.forward_zones]]` are used when `mode=forward` or `forward_on_fail=true`. Editable in Settings.
- Outbound schemes: `host:53` (UDP), `tls://host:853` (DoT, optional `#sni`), `https://host/dns-query` (DoH).

## TLS (DoT / DoH / DoH3 / DoQ)
- Minimum TLS 1.3 for encrypted DNS listeners.
- Place certs in `certs/` (`cert_file` / `key_file` in TOML).

## DNSSEC validation (recursive / forward)
- Modes: `off` | `opportunistic` | `validate` (`[resolver] dnssec_mode`).
- Trusts upstream AD; verifies in-message RRSIG when DNSKEY is present.
- NXDOMAIN/NODATA: consumes NSEC3/NSEC denial covers when present (incomplete proofs do not SERVFAIL).
- Full root-anchored chain-of-trust still deferred.

## Backup / restore
- `GET /api/v1/backup` — export zones + records (+ DS if signing).
- `POST /api/v1/backup` — import `{ "zones": [ { "name", "records": [...] } ] }`.
- UI: Settings → Download / Restore backup.

## DNSSEC signing (authoritative)
- Enable via zone meta `dnssec_enabled` (DB) or `POST /api/v1/zones/{name}/dnssec` (`{ "algorithm": "ECDSAP256SHA256|ED25519|ECDSAP384SHA384|RSASHA256", "nsec3": true }`).
- Trigger manual ZSK rollover via `POST /api/v1/zones/{name}/dnssec` with `{ "action": "rollover" }`.
- Keys & policy metadata stored under `data/dnssec/<zone>/`.
- Answers signed when client sets DO; DNSKEY queries return keys + RRSIG; NXDOMAIN emits NSEC3 (when enabled) or NSEC + RRSIG.
- Publish the returned **DS** at the parent / registrar.
- HSM-backed DNSSEC keys remain deferred.

## Live Control Plane ↔ Dataplane Synchronization
- Mutations on whitelist, blacklist, Query ACL, Rate Limiting/Auto-Ban, and authoritative zone records apply **without restarting `dnsdist` or `Unbound`**:
  - `dnsdist` receives live policy/cache/DynBlock commands over Control Socket (`dnsdistctl`: `addDynamicBlock`, `expungeByName`, `clearCache`, allow/deny set updates).
  - `Unbound` receives live local-zone/cache flush commands over `unbound-control`.
  - Authoritative zone changes invalidate affected names in `dnsdist` packet cache and trigger `NOTIFY` to secondaries.

## Technitium-Parity Console & APIs
- **3-Tier Cache Explorer & Purge:** `GET /api/v1/cache/stats`, `GET /api/v1/cache/inspect`, `POST /api/v1/cache/flush` (`scope`: `all|dnsdist|unbound|go`, optional `domain` flush).
- **RRL / Auto-Ban / DynBlock Manager:** `GET /api/v1/security/blocks`, `POST /api/v1/security/ban`, `DELETE /api/v1/security/ban?prefix=...`, `POST /api/v1/security/dynblocks/clear`.
- **Live Query Stream (20k In-Memory Ring Buffer):** `GET /api/v1/queries/live` and `GET /api/v1/queries/stream` (SSE; samples `dnsdist` top-responses/live Go queries into RAM with zero Postgres write amplification).
- **DNS Client & Root Trace:** `POST /api/v1/tools/lookup` (UDP/TCP/DoT/DoH with custom server target + DO/CD/RD flags) & `POST /api/v1/tools/trace` (iterative root-to-authoritative hop trace).
- **BIND Zone Import / Export:** `POST /api/v1/zones/import` (RFC 1035 master text) & `GET /api/v1/zones/{name}/export`.
- **API Tokens CRUD:** `GET/POST/DELETE /api/v1/auth/tokens` (SHA-256 hashed scoped Bearer keys).
- **UI EN/ID Switcher:** Sidebar language toggle persists `powersvx_lang` (`en` / `id`).

## AXFR sync (Tools)
- Settings → Tools → **AXFR**. Three complementary panels:
  - **Outbound secondary (NOTIFY):** default **disabled**. Default sources Kominfo secondaries `182.23.79.202` / `139.255.196.202` (editable; also `[kominfo_sync] targets` / `axfr_sync_targets`). When enabled those IPs may AXFR/IXFR without global `allow_axfr` / TSIG; zone changes send NOTIFY. **Sync now** walks all zones (NOTIFY → SOA check). Persisted in `runtime-settings.json` as `axfr_sync_enabled` + `axfr_sync_targets` (legacy `kominfo_sync_enabled` still accepted).
  - **Filter feeds (slave AXFR):** PowerSVX as slave pulls configured filter zones via streaming **AXFR** or incremental **IXFR** from upstream masters (with optional **`tsig_key`** RFC 2845 signing and authorized master/TSIG `NOTIFY` triggers). Each policy caches its parsed names in `data/blocklist/feeds/` so partial or skipped refreshes never wipe other active feeds when merging into `domains.cdb`. Serials live in `data/rpz-axfr-state.json`. Default **`axfr_update_interval = 86400`** (24h).
  - **Secondary (Slave) Authoritative Zones:** Replicate full authoritative DNS zones from upstream primaries using SOA pre-check (RFC 1982), true RFC 1995 **IXFR** delta + **AXFR** fallback, optional **TSIG** (`tsig_key`), SOA `Refresh`/`Retry`/`Expire` timers, disk record persistence (`data/secondary-zones/`), and automatic `authzones.cdb` + Unbound/dnsdist dataplane sync.

## GeoDNS
- Uses MaxMind-compatible MMDB (`[geodns] database_path`).
- **Docker default:** DB-IP Country Lite (`/data/dbip-country-lite.mmdb`), auto-downloaded by `deploy/docker/entrypoint.sh` on start if missing or older than ~35 days (CC BY 4.0 — attribute [DB-IP](https://db-ip.com)).
- Skip with `GEODB_AUTO_DOWNLOAD=0`. Override path with `GEODB_PATH`.
- Lookup uses City DB when present, otherwise Country DB.

## Query logs & Grafana Security Defaults
- PostgreSQL query logging requires `query_log_enabled = true`; `query_log_mask_ip = true` masks /24 (IPv4) or /48 (IPv6); hourly purge respects `query_log_retention_days`.
- High-rate live telemetry uses the in-memory 20k ring buffer rather than writing every packet synchronously to PostgreSQL.
- Grafana container binds `127.0.0.1:3000` with `GF_AUTH_ANONYMOUS_ENABLED=false` (expose only via TLS reverse proxy / SSH tunnel).
- Lua plugins run with a 50ms execution timeout context (`plugin.go`) so buggy scripts cannot stall workers.

## Reload
- `SIGHUP` / `systemctl reload powersvx` reloads `runtime-settings.json` flags, query ACL, and plugins.
- Data directory: `--data-dir` (default `./data`; Linux package uses `/var/lib/powersvx`).

## Linux deploy & Docker CD (Auto-Update)
- See `deploy/linux/README.md` — systemd unit, `configs/powersvx.linux.toml`, `install.sh`, Docker override.
- **Docker CD (`ghcr.io/hendrax5/powersvx`):**
  - Tag pushes (`v*`) build and push multi-arch images (`linux/amd64`, `linux/arm64`) as `:latest` + `:<version>` via `.github/workflows/release.yml`, and attach standalone Linux binaries (`make_latest: false` keeps `filter-seed` intact). Pushes to `main` publish `:edge` for staging.
  - **Watchtower (`nickfedor/watchtower`):** runs via `docker-compose.yml` with `WATCHTOWER_LABEL_ENABLE=true`, `WATCHTOWER_CLEANUP=true`, and `WATCHTOWER_SCHEDULE=0 15 3 * * *` (`TZ=Asia/Jakarta`, 03:15 WIB daily). Only `powersvx` carries `com.centurylinklabs.watchtower.enable=true` — `dnsdist`, `Unbound`, and `Postgres` are never auto-restarted so `:53` stays uninterrupted.
  - Ensure `ghcr.io/hendrax5/powersvx` package visibility is **Public** on GitHub (or run `docker login ghcr.io` on nodes if kept private).

## Deferred (enterprise)
- Raft HA / multi-node failover
- Redis L3 shared cache
- Full OIDC/SAML SSO
- True incremental IXFR journal
- Root-anchored DNSSEC chain-of-trust
- DHCP (only if LAN appliance is a product goal)
- Multi-tenancy
- HSM-backed DNSSEC keys
