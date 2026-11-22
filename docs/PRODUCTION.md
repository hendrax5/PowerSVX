# PowerSVX production notes (Raft clustering deferred)

## DNS dataplane (dnsdist+CDB) vs control-plane (PowerSVX)

On production hosts (`POWERSVX_DNS_DATAPLANE=dnsdist`, default):

| Role | Process | Ports |
|------|---------|-------|
| Public DNS + CDB blocklist + bank whitelist | **dnsdist** | `:53` |
| Recurse-only backend | **Unbound** | `127.0.0.1:5353` |
| UI / API / AXFR→CDB sync / Kominfo outbound AXFR | **PowerSVX** (Control Plane) | `:5380` |
| Authoritative Zones and Secondary Zones (Auth Backend) | **PowerSVX** | `127.0.0.1:5354`, reached only through dnsdist |

- Komdigi AXFR / hosts feeds → per-policy feed caches (`data/blocklist/feeds/`) merged into `data/blocklist/domains.cdb` (full list, mmap; no Unbound 1.5M RPZ cap). Banks filtered from CDB + dnsdist `SuffixMatchNode`.
- **CDB refresh:** RFC 1982 serial comparison on SOA check first (skip unchanged policies while preserving their entries in the merged CDB); if serial advanced, stream AXFR or apply incremental **IXFR** delta with automatic AXFR fallback. Serials in `data/rpz-axfr-state.json`. `dnsdist` forwards `OpcodeNotify` directly to the Auth Backend (`127.0.0.1:5354`).
- Spoof blocked A → `139.255.196.196` (Komdigi sinkhole). Regen conf: `deploy/linux/gen-dnsdist-conf.sh`.
- **The Go process never answers public queries.** The Auth Backend binds loopback (`[server] bind_address = "127.0.0.1"`, port `5354`) and answers only Authoritative Zones and Secondary Zones; a name outside every hosted zone gets REFUSED, and so does any query whose source address is not loopback. Recursion, the resolver cache, the Filter check, rate limits, bans and query access rules run in dnsdist and Unbound only; the Control Plane stores those rules and pushes them. See `docs/adr/0001-dnsdist-is-the-only-dataplane.md`.
- **Source addresses behind the Dataplane.** Other hosts can no longer reach the Auth Backend port directly. Queries, NOTIFY, zone transfers and updates arrive through dnsdist, so the handler sees the Dataplane's loopback address as the source. IP allow lists (secondary master list, `[transfer] allow_from`, `[update] allow_from`, Kominfo target addresses) and split-horizon or GeoDNS selection therefore do not distinguish clients; TSIG still gates transfers, updates and NOTIFY. Client-aware handling behind the Dataplane is tracked in ticket #36.

### Removed: Unbound on the public port

The mode in which Unbound answered clients directly on `:53` with RPZ zonefiles (`POWERSVX_DNS_DATAPLANE=unbound`, also spelled `external`) has been **removed**, together with its zonefile Filter sync, `unbound-rpz-guard.sh`, `POWERSVX_UNBOUND_QUERYLOG`, `POWERSVX_RPZ_MAX_ENTRIES` and `POWERSVX_UNBOUND_MODE=dataplane`. Unbound stays, as the recursive backend behind dnsdist on `127.0.0.1:5353`; its control interface still serves statistics, the Cache Explorer and cache flushing.

**Migrate a node to dnsdist:**

1. Set `POWERSVX_DNS_DATAPLANE=dnsdist` (or remove the line: it is the default on a host deployment) in the environment or `.env`.
2. Regenerate the configs: `bash deploy/linux/gen-unbound-conf.sh` and `bash deploy/linux/gen-dnsdist-conf.sh`.
3. Recreate the stack with `bash deploy/linux/apply-update.sh`. The first Filter sync fills the CDB (`data/blocklist/`); the old `data/unbound-rpz/*.rpz` zonefiles are no longer read and can be deleted.

`POWERSVX_ALLOW_LEGACY_DATAPLANE` no longer has any effect: there is no code left to run the mode, and both the update and the Control Plane refuse it.

### Removed Dataplane modes: the guard

Only the dnsdist Dataplane exists. The `unbound`, `external` and `powersvx` (Go resolver) modes are removed. A node configured for any of them is never updated silently:

- The Control Plane exits at start with a message naming the configured mode and the fix.
- `deploy/linux/apply-update.sh` and `bootstrap-node.sh` run `deploy/linux/dataplane-guard.sh` first and stop with the same message before touching containers.
- An unset `POWERSVX_DNS_DATAPLANE` means dnsdist everywhere. In local development there is no Dataplane to push to: the process still starts as a Control Plane, and its pushes to dnsdist and Unbound fail quietly.
- To fix a node: set `POWERSVX_DNS_DATAPLANE=dnsdist`, regenerate configs with `deploy/linux/gen-dnsdist-conf.sh`, and recreate the stack.
- `python ops/probe.py` prints each node's configured mode.

### Unbound forwards to itself (ticket #40)

Before this fix the shipped host configuration said `[resolver] mode = "forward"` with `forwarders = ["127.0.0.1:5353"]`. The Control Plane copied that into Unbound's runtime configuration as `forward-zone: name: "."`, so Unbound forwarded every query to its own listener: every name outside the hosted zones failed, as soon as Unbound loaded the file (at start, or on the reload the Control Plane triggers).

What changed:

- The shipped host configuration is `mode = "recursive"` with no forwarders: Unbound recurses by itself.
- The Control Plane never writes a forwarder that points back into the Dataplane: a loopback address (`127.0.0.1`, `::1`, `localhost`) on Unbound's own port (`POWERSVX_UNBOUND_BACKEND_PORT`, default `5353`) or on port `53` (dnsdist, which sends the query back to Unbound). It skips it, logs a `WARN` (`resolver forwarder skipped`) and shows it in `GET /api/v1/health` under `checks.unbound_runtime.skipped_forwarders` (status `degraded`). It does not matter whether the forwarder came from the TOML file, the saved settings (`data/runtime-settings.json`) or the console: all of them go through the same writer. A real forwarder keeps working.
- `bootstrap-node.sh` and `apply-update.sh` run `deploy/linux/check-unbound-conf.sh` after generating the configs and before creating or recreating any container. It refuses to continue, naming the file, when `unbound.conf` has the control interface disabled or does not load the runtime files, when `data/unbound-rpz/runtime-zones.conf` has a forward-zone pointing at Unbound or dnsdist, or when `unbound-checkconf` in the pinned Unbound image rejects the configuration.
- The readiness check can fail on broken recursion: `dns-ready.sh -r` resolves a fresh label under a real domain (`example.com` by default), which only recursion can answer. `.invalid` is answered by Unbound itself, so `-u invalid` passes while recursion is broken; it is kept as the local-path check. The dnsdist healthcheck, `bootstrap-node.sh` and `apply-update.sh` use `-r` (one real query per run; the healthcheck runs it every 30 s). `-r` also fails while the node cannot reach the Internet.
- A failed Unbound reload (control interface disabled or unreachable) is logged as an `ERROR` and shown in `checks.unbound_runtime.reload_error`; the Control Plane retries for about 9 minutes (after 5, 15, 30 and 60 s, then 2 and 5 minutes) and the health output returns to normal when one works.

**Recognise the problem on an existing node** (do this before updating it; `apply-update.sh` now refuses to continue on such a node):

```sh
docker exec powersvx-unbound-1 unbound-control list_forwards      # a line like ". IN forward 127.0.0.1" is the loop
grep -n -A3 'forward-zone' data/unbound-rpz/runtime-zones.conf    # forward-addr: 127.0.0.1@5353
grep -n control-enable configs/unbound/unbound.conf               # "no" means the Control Plane cannot reload Unbound
bash deploy/linux/dns-ready.sh -r                                 # fails (SERVFAIL, or no answer) while recursion is broken
```

If `list_forwards` cannot connect, the control interface is disabled: Unbound is still running the configuration it started with, and the loop is in the file on disk, waiting for the next restart of Unbound (an update recreates it).

**Repair:**

1. In the console (Settings, resolver mode) set the mode to **recursive** and clear the forwarders, or edit `configs/powersvx.docker.host.toml` (`mode = "recursive"`, `forwarders = []`). Settings saved earlier in `data/runtime-settings.json` override the file, so check them: `grep -E 'resolver_mode|forwarders' data/runtime-settings.json`.
2. Remove the `forward-zone:` block with `name: "."` from `data/unbound-rpz/runtime-zones.conf` (or empty the file; the Control Plane rewrites it). With the new Control Plane this block is not written again.
3. Regenerate and reload: `bash deploy/linux/gen-unbound-conf.sh` (control interface on `127.0.0.1:8953`), then `docker exec powersvx-unbound-1 unbound-control reload_keep_cache`, or recreate Unbound with `bash deploy/linux/apply-update.sh`.
4. Verify: `unbound-control list_forwards` shows no `.` entry and `bash deploy/linux/dns-ready.sh -r` exits 0.

**Why a node can have the control interface disabled.** `deploy/linux/gen-unbound-conf.sh` has always written `control-enable: yes` on `127.0.0.1:8953`. Two other files in the field say `control-enable: no`: the sample `configs/unbound/unbound.conf` that used to be committed (it also lacked the `include:` lines for the Control Plane's runtime files), and the default configuration the `mvance/unbound` image writes when no `unbound.conf` is mounted. A node runs one of them when the generated file was overwritten or never produced before the container started (for example `git checkout` or a tarball restoring the sample after generation, or `docker compose up` before `gen-unbound-conf.sh`). We could not establish which of these happened on the two lab nodes that showed it. The sample now matches the generator, and `check-unbound-conf.sh` refuses to continue on a configuration with the control interface disabled.

## Query ACL
- `[acl] allow_query` — CIDRs/IPs allowed to query DNS. **Empty = allow all.**
- `[acl] deny_query` — always refused (wins over allow).
- Editable in UI Settings (no restart). The Control Plane stores the rules and writes them to dnsdist, which refuses denied clients.
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
- Default resolver mode is **recursive**. Global `[resolver] forwarders` plus optional `[[resolver.forward_zones]]` are used when `mode=forward` or `forward_on_fail=true`. Editable in Settings. Never list Unbound's own address (`127.0.0.1:5353`) or dnsdist (`:53`) as a forwarder: the Control Plane skips it (see "Unbound forwards to itself").
- Outbound schemes: `host:53` (UDP), `tls://host:853` (DoT, optional `#sni`), `https://host/dns-query` (DoH).

## TLS (DoT / DoH / DoQ)
- dnsdist terminates DoT, DoH and DoQ. The Go process starts no DoT, DoH or DoQ listener; `cert_file` and `key_file` are read by dnsdist and ACME only.
- Place certs in `certs/` (`cert_file` / `key_file` in TOML).

## DNSSEC validation
- Validation is done by Unbound. The Go process no longer validates; `[resolver] dnssec_mode` is pushed to the Unbound runtime config.

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

## Core Profile and Observability Profile
- Core: `dnsdist`, `unbound`, `powersvx`, `watchtower`. Observability: `postgres` (query-log history only), `prometheus`, `grafana`, `node-exporter`. Core runs the Control Plane with the database disabled; without Postgres the console says query history is unavailable.
- `POWERSVX_PROFILE=core` in `.env` runs the Core Profile only; unset or `full` runs everything. Bootstrap selects `core` by itself on hosts under 4 GB of memory and saves it to `.env`. Details and commands: `deploy/linux/README.md`.
- Existing nodes are unaffected until `POWERSVX_PROFILE=core` is set: the plain `docker compose ... up -d` and `apply-update.sh` keep starting everything.

## Reload
- `SIGHUP` / `systemctl reload powersvx` reloads `runtime-settings.json` flags and the query ACL.
- Data directory: `--data-dir` (default `./data`; Linux package uses `/var/lib/powersvx`).

## Linux deploy & Docker CD (Auto-Update)
- See `deploy/linux/README.md` — systemd unit, `configs/powersvx.linux.toml`, `install.sh`, Docker override.
- **Docker CD (`ghcr.io/hendrax5/powersvx`):**
  - Tag pushes (`v*`) build and push multi-arch images (`linux/amd64`, `linux/arm64`) as `:latest` + `:<version>` via `.github/workflows/release.yml`, and attach standalone Linux binaries (`make_latest: false` keeps `filter-seed` intact). Pushes to `main` publish `:edge` for staging.
  - **Watchtower (`nickfedor/watchtower`):** runs via `docker-compose.yml` with `WATCHTOWER_LABEL_ENABLE=true`, `WATCHTOWER_CLEANUP=true`, `DOCKER_CONFIG=/config` (mounted from `${DOCKER_CONFIG_DIR:-/root/.docker}`), and `WATCHTOWER_SCHEDULE=0 15 3 * * *` (`TZ=Asia/Jakarta`, 03:15 WIB daily). Only `powersvx` carries `com.centurylinklabs.watchtower.enable=true` — `dnsdist`, `Unbound`, and `Postgres` are never auto-restarted so `:53` stays uninterrupted.
  - **Public vs Private GHCR:** If `ghcr.io/hendrax5/powersvx` stays **Private**, create a GitHub PAT (`read:packages` scope only) and either run `sudo docker login ghcr.io -u hendrax5` on each node or set `GHCR_USER` + `GHCR_TOKEN` in `.env` — Watchtower reads `/root/.docker/config.json` automatically via `/config`.

## Deferred (enterprise)
- Raft HA / multi-node failover
- Redis L3 shared cache
- Full OIDC/SAML SSO
- True incremental IXFR journal
- Root-anchored DNSSEC chain-of-trust
- DHCP (only if LAN appliance is a product goal)
- Multi-tenancy
- HSM-backed DNSSEC keys
