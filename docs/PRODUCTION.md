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
- **Source addresses behind the Dataplane.** Other hosts cannot reach the Auth Backend port directly: queries, NOTIFY, zone transfers and updates arrive through dnsdist. dnsdist passes the real client address to the Auth Backend in a PROXY protocol v2 header, which is accepted only from a loopback peer, so split-horizon views, GeoDNS, the secondary master list, `[transfer] allow_from`, `[update] allow_from`, Kominfo target addresses and the query log use the client. See "PROXY protocol: updating an existing node" below and `docs/adr/0003-proxy-protocol-for-the-client-address.md`.

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

### Leftover TPROXY intercept (2.0 upgrade)

Older versions could install a kernel TPROXY intercept from the console (Settings, TPROXY). The transparent listener it pointed at is gone, and the console can no longer remove the rules. `[server] tproxy` is removed too: a configuration that still sets it starts with one warning (`docs/CONFIG-REMOVED.md`).

`deploy/linux/apply-update.sh` runs `deploy/linux/tproxy-leftover.sh` and prints a warning when it finds a leftover. It removes nothing and never fails the update. To check by hand, as root:

```
nft list table inet powersvx_tproxy        # a table means the intercept is still installed
ip rule show | grep 'lookup 100'           # "fwmark 0x1 lookup 100" (priority 100)
ip -6 rule show | grep 'lookup 100'
ip route show table 100                    # "local default dev lo"
ip -6 route show table 100
```

Remove it, only if nothing else on the host uses routing table 100 (the old code always used table 100 and fwmark 0x1; use the mark the `ip rule` line shows if it differs):

```
nft delete table inet powersvx_tproxy
ip rule del fwmark 0x1 lookup 100 priority 100
ip -6 rule del fwmark 0x1 lookup 100 priority 100
ip route flush table 100
ip -6 route flush table 100
```

Until it is removed, the host keeps diverting client DNS to port 53 with TPROXY, a path PowerSVX 2.0 no longer sets up or tests. Remove it, and use DNAT (MikroTik / iptables `dstnat`) to bring client queries to the Dataplane.

### Containers on the default Docker bridge cannot resolve names (ticket #23)

`deploy/linux/os-hardening.sh` used to install `iptables -t raw -A PREROUTING -p udp --dport 53 -j NOTRACK`. That rule also matched packets a container on the default bridge sends to an outside resolver (forwarded, not addressed to the node), so they were never tracked and NAT could not map the replies back: UDP/53 from such a container failed while TCP/53 and host-network UDP/53 worked. The rule now carries `-m addrtype --dst-type LOCAL`: only queries addressed to the node (the Dataplane) stay untracked. The `OUTPUT --sport 53` rule is unchanged.

Upgrade: `apply-update.sh` runs `os-hardening.sh`, which runs `deploy/linux/notrack-dns.sh`. It adds the narrow rule first, then deletes the old broad rule until none is left, so queries to the node are never without a rule. It does not touch other rules. A broad rule in a saved `/etc/iptables/rules.v4` is rewritten to the narrow one. The rules are not otherwise persisted by PowerSVX: they come back from `os-hardening.sh` at the next update or bootstrap. To check by hand, as root:

```
deploy/linux/check-notrack.sh -u <upstream resolver IP>
# or: docker run --rm --entrypoint drill mvance/unbound:1.22.0 -Q -p 53 @<upstream> example.org A
```

The script prints `FAIL broad rule present` while the old rule exists and probes a bridge container with UDP. The Dataplane path (host networking, dnsdist on the node's own addresses) is unchanged, so no throughput change is expected.

### Unbound forwards to itself (ticket #40)

Before this fix the shipped host configuration said `[resolver] mode = "forward"` with `forwarders = ["127.0.0.1:5353"]`. The Control Plane copied that into Unbound's runtime configuration as `forward-zone: name: "."`, so Unbound forwarded every query to its own listener: every name outside the hosted zones failed, as soon as Unbound loaded the file (at start, or on the reload the Control Plane triggers).

What changed:

- The shipped host configuration is `mode = "recursive"` with no forwarders: Unbound recurses by itself.
- The Control Plane never writes a forwarder that points back into the Dataplane: a loopback address (`127.0.0.1`, `::1`, `localhost`) on Unbound's own port (`POWERSVX_UNBOUND_BACKEND_PORT`, default `5353`) or on port `53` (dnsdist, which sends the query back to Unbound). It skips it, logs a `WARN` (`resolver forwarder skipped`) and shows it in `GET /api/v1/health` under `checks.unbound_runtime.skipped_forwarders` (status `degraded`). It does not matter whether the forwarder came from the TOML file, the saved settings (`data/runtime-settings.json`) or the console: all of them go through the same writer. A real forwarder keeps working.
- The saved settings file overrides the TOML, and any save in the console persists the whole settings structure, so a node where someone ever saved the settings page keeps the old `forward` / `127.0.0.1:5353` values in `data/runtime-settings.json` whatever the TOML says. The settings API now answers `400` to a forwarder (global or per zone) that is Unbound's own listener or dnsdist, and the console's "Unbound backend" preset now means mode `recursive` with no forwarders. At start the Control Plane rewrites such saved settings (it removes the looping forwarders, switches a `forward` mode left with none to `recursive`, and logs `saved resolver settings pointed Unbound at itself`). Saving other settings no longer writes an old looping value back. The render-time guard above still protects every other source.
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

1. In the console (Settings, resolver mode) set the mode to **recursive** and clear the forwarders, or edit `configs/powersvx.docker.host.toml` (`mode = "recursive"`, `forwarders = []`). Settings saved earlier in `data/runtime-settings.json` override the file, so check them: `grep -E 'resolver_mode|forwarders' data/runtime-settings.json` (a Control Plane with this fix rewrites that file at its next start).
2. Remove the `forward-zone:` block with `name: "."` from `data/unbound-rpz/runtime-zones.conf` (or empty the file; the Control Plane rewrites it). With the new Control Plane this block is not written again.
3. Regenerate and reload: `bash deploy/linux/gen-unbound-conf.sh` (control interface on `127.0.0.1:8953`), then `docker exec powersvx-unbound-1 unbound-control reload_keep_cache`, or recreate Unbound with `bash deploy/linux/apply-update.sh`.
4. Verify: `unbound-control list_forwards` shows no `.` entry and `bash deploy/linux/dns-ready.sh -r` exits 0.

**Why a node can have the control interface disabled.** `deploy/linux/gen-unbound-conf.sh` has always written `control-enable: yes` on `127.0.0.1:8953`. Two other files in the field say `control-enable: no`: the sample `configs/unbound/unbound.conf` that used to be committed (it also lacked the `include:` lines for the Control Plane's runtime files), and the default configuration the `mvance/unbound` image writes when no `unbound.conf` is mounted. A node runs one of them when the generated file was overwritten or never produced before the container started (for example `git checkout` or a tarball restoring the sample after generation, or `docker compose up` before `gen-unbound-conf.sh`). We could not establish which of these happened on the two lab nodes that showed it. The sample now matches the generator, and `check-unbound-conf.sh` refuses to continue on a configuration with the control interface disabled.

## PROXY protocol: updating an existing node

Two settings meet here: `POWERSVX_AUTH_PROXY_PROTOCOL` in `gen-dnsdist-conf.sh` (default `1`: dnsdist sends a PROXY v2 header to the Auth Backend, adds no ECS, and has no packet cache for hosted zones) and `[server] proxy_protocol` in the Control Plane TOML (`optional` by default, also `required` and `off`).

| State of the node | What happens |
|---|---|
| New Control Plane image, dnsdist configuration generated before this change | Works. dnsdist sends plain queries, the Control Plane accepts them in `optional` mode. Every client still appears as `127.0.0.1`: views, GeoDNS and the allow lists do not distinguish clients, as before. |
| Dnsdist configuration regenerated and dnsdist recreated, new Control Plane | Real client addresses everywhere. |
| New Control Plane, `proxy_protocol = "required"`, dnsdist configuration not yet regenerated | Hosted zones stop answering: a plain query is refused in `required` mode. Switch to `required` only after the regenerated dnsdist is running. A plain loopback query is accepted only in `optional` mode. |
| Control Plane rolled back to an image without PROXY support while dnsdist sends headers | Every query for a hosted zone fails. Set `POWERSVX_AUTH_PROXY_PROTOCOL=0`, run `bash deploy/linux/gen-dnsdist-conf.sh`, recreate dnsdist, then roll back. |

Order in `apply-update.sh`: it generates the dnsdist configuration into `configs/dnsdist/dnsdist.conf.new`, builds and recreates the Control Plane, waits until `/api/v1/health` answers (up to 120 s), and only then moves the new file into place and recreates `unbound` and `dnsdist`. dnsdist therefore never starts sending headers to a Control Plane that cannot read them. If the Control Plane does not come up, the script stops before replacing the dnsdist configuration and leaves `dnsdist.conf.new` for you. Watchtower replaces only the Control Plane image, so it is the same safe order. `bootstrap-node.sh` on a new node generates both sides from this version.

## dnsdist web password and API key (ticket #56)

dnsdist serves a web server and API on `127.0.0.1:8083`, protected by a password and an API key. The Control Plane reads statistics and issues runtime commands through it. Both values live in the node's `.env` as `POWERSVX_DNSDIST_WEB_PASSWORD` and `POWERSVX_DNSDIST_API_KEY` (mode 600). There is no built-in default: `gen-dnsdist-conf.sh` refuses to write a configuration without them, unless `POWERSVX_ALLOW_DEFAULT_DNSDIST_CREDENTIALS=1` is set (local development and tests only), and the compose file passes an unset value to the Control Plane as empty, never as a default.

`bootstrap-node.sh` and `apply-update.sh` run `deploy/linux/ensure-dnsdist-credentials.sh`, which creates random values (`openssl rand`, else `/dev/urandom`) for whichever of the two is missing or empty in `.env`, keeps the file at mode 600, leaves present values alone and never prints a value.

| State of the node | What happens |
|---|---|
| `.env` has both values | Nothing is created. The generator writes them into the dnsdist configuration, the Control Plane gets them from compose. They agree. |
| `.env` lacks them (node set up by hand, or `.env` edited), running dnsdist still uses the old public defaults | `apply-update.sh` creates new values and generates `dnsdist.conf.new` with them. The Control Plane is recreated first (as for PROXY protocol, above) and from then on holds the new values; dnsdist is recreated with the new configuration a few seconds later, after the health wait. In that window the Control Plane's statistics and runtime-control calls to dnsdist are refused (401) and recover on their own. DNS answering is not affected. |
| The Control Plane does not become healthy within 120 s | `apply-update.sh` stops before replacing the dnsdist configuration (see above). The Control Plane already holds the new values, so the same refusals persist until you move `configs/dnsdist/dnsdist.conf.new` into place and recreate dnsdist. |
| Generator run by hand without the values in the environment | It fails with a message. Export the two values from `.env` first (or run `apply-update.sh`). |

Rotating the values (every command from the repository root on the node; nothing prints a secret):

1. Remove both lines: `sed -i '/^POWERSVX_DNSDIST_WEB_PASSWORD=/d;/^POWERSVX_DNSDIST_API_KEY=/d' .env`
2. Create new values: `sh deploy/linux/ensure-dnsdist-credentials.sh .env` (prints only `created ...` lines).
3. Regenerate the configuration from the new values: `set -a; . ./.env; set +a; bash deploy/linux/gen-dnsdist-conf.sh configs/dnsdist/dnsdist.conf.new` (source `.env` only if every line in it is shell-safe; otherwise export the two variables as `apply-update.sh` does).
4. Recreate the Control Plane first, so it holds the new values: `docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml up -d --no-deps --force-recreate powersvx`, and wait for `curl -fsS http://127.0.0.1:5380/api/v1/health`.
5. Move the configuration into place and recreate dnsdist: `mv -f configs/dnsdist/dnsdist.conf.new configs/dnsdist/dnsdist.conf`, then `docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml up -d --no-deps --force-recreate dnsdist`. Only dnsdist and the Control Plane restart; between steps 4 and 5 the Control Plane's dnsdist calls are refused, as in the table. Port 53 is interrupted only for the dnsdist recreation. Add the Core Profile overlay `-f deploy/linux/docker-compose.core.yml` to both compose commands on a Core Profile node.

The simplest way is `bash deploy/linux/apply-update.sh` after step 1: it does steps 2 to 5 in this order.

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
- **Outbound IXFR** sends the changes since the client's serial for an unsigned zone, and the whole zone for a signed one (RFC 1982 serial check; clients up-to-date get current SOA only).
- **DNSSEC-signed zones** are transferred signed (DNSKEY, RRSIGs, NSEC/NSEC3 chain, NSEC3PARAM), so any secondary serves a zone that validates against your DS; signing keys never leave this node. The signatures in transfers are valid `[transfer] signature_validity_days` (default 30) and renewed every `signature_refresh_days` (default 7, held to at most half of validity): the zone's SOA serial moves once per interval and secondaries are notified. A secondary must pull at least once within validity minus refresh days (23 by default). Split-horizon: a signed zone is sent as the requesting address's view of it. See `docs/adr/0004-primary-signs-secondaries-serve-what-they-receive.md`.
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
- Place certs in `certs/`. dnsdist reads them; the `[server.tls]` section and `dot_port`, `doh_port`, `doq_port` are ignored since version 2, see [CONFIG-REMOVED.md](CONFIG-REMOVED.md) (it lists every key that no longer has a meaning).

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
- **Cache Explorer & Purge (dnsdist, Unbound):** `GET /api/v1/cache/stats`, `GET /api/v1/cache/inspect`, `POST /api/v1/cache/flush` (`scope`: `all|domain|zone|type|negative`, optional `domain` flush).
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

## Memory and the Filter rebuild (ticket #65)

`deploy/linux/calc-mem-env.sh` sets the container limit to 30% of host RAM and `GOMEMLIMIT` to 90% of that. A host with 2 GB gets about a 614 MB container limit and a `GOMEMLIMIT` of about 553 MB; 8 GB gets 2.4 GB and about 2.1 GB.

- **What a rebuild costs.** The Filter rebuild streams the feed caches through a temporary file, `domains.names.tmp` in the blocklist directory (about the size of `domains.txt`, removed when the rebuild ends or at the next start). Memory is a de-duplication table of about 8 bytes per name (sized from the feed file sizes, grown by half when needed) and, after that table is freed, the CDB hash tables at 8 bytes per name. Names never sit in memory all at once. Measured on 10 million synthetic names (output byte-identical to the former rebuild): peak Go heap 189 MB and peak RSS 207 MB, against 1742 MB and 1830 MB before. That is about 19 bytes per name, so 1 million names cost about 20 MB. IXFR deltas are merged into the feed cache the same streaming way and cost memory for the delta only.
- **2 GB host.** A 10 million name rebuild peaks near 210 MB, under the 553 MB `GOMEMLIMIT`, and was run inside a 614 MB container limit to confirm. The rebuild stays under `GOMEMLIMIT` up to roughly 25 million names; beyond that the Go runtime collects harder and the rebuild slows down, and the watchdog (below) still only acts on a real overrun. There is no separate degraded mode: the rebuild is already the on-disk, slower variant. Leave free disk for `domains.names.tmp` and the two `.tmp` outputs while a rebuild runs (about 1 GB for 10 million names).
- **Watchdog.** `internal/watchdog` samples every 15 s and exits the Control Plane (code 2, Docker restarts it) after 8 samples in a row, two minutes, with in-use memory above 115% of `GOMEMLIMIT`. In-use memory is the Go runtime's total minus idle heap: heap holding objects, stacks and runtime structures. Heap the runtime keeps for reuse, or has already handed back to the OS, is not counted, because it is free. The earlier check used the runtime's total, which does not fall after a burst of work, so a finished rebuild could be killed. Each warning logs `in_use_mb`, `heap_inuse_mb`, `sys_mb`, `threshold_mb`, `limit_mb` and `streak`. A rebuild also returns freed memory to the OS when it ends.

## Reload
- `SIGHUP` / `systemctl reload powersvx` reloads `runtime-settings.json` flags and the query ACL.
- Data directory: `--data-dir` (default `./data`; Linux package uses `/var/lib/powersvx`).

## Linux deploy & Docker CD (Auto-Update)
- See `deploy/linux/README.md` — systemd unit, `configs/powersvx.linux.toml`, `install.sh`, Docker override.
- **Docker CD (`ghcr.io/hendrax5/powersvx`):**
  - Tag pushes (`v*`) build and push multi-arch images (`linux/amd64`, `linux/arm64`) as `:latest` + `:<version>` via `.github/workflows/release.yml`, and attach standalone Linux binaries (`make_latest: false` keeps `filter-seed` intact). Pushes to `main` publish `:edge` for staging.
  - **Watchtower (`nickfedor/watchtower`):** runs via `docker-compose.yml` with `WATCHTOWER_LABEL_ENABLE=true`, `WATCHTOWER_CLEANUP=true`, `DOCKER_CONFIG=/config` (mounted from `${DOCKER_CONFIG_DIR:-/root/.docker}`), and `WATCHTOWER_SCHEDULE=0 15 3 * * *` (`TZ=Asia/Jakarta`, 03:15 WIB daily). Only `powersvx` carries `com.centurylinklabs.watchtower.enable=true` — `dnsdist`, `Unbound`, and `Postgres` are never auto-restarted so `:53` stays uninterrupted.
  - **Public vs Private GHCR:** If `ghcr.io/hendrax5/powersvx` stays **Private**, create a GitHub PAT (`read:packages` scope only) and either run `sudo docker login ghcr.io -u hendrax5` on each node or set `GHCR_USER` + `GHCR_TOKEN` in `.env` — Watchtower reads `/root/.docker/config.json` automatically via `/config`. Without either, Watchtower gets `401` and never updates the node; see "Watchtower and the private GHCR image" below for how to check and fix it.

## Watchtower and the private GHCR image

`ghcr.io/hendrax5/powersvx` is a **private** package (checked with the GitHub API). Anonymous pulls get `401`, so a node can auto-update only if Watchtower has a registry login.

**How Watchtower authenticates.** `docker-compose.yml` mounts `${DOCKER_CONFIG_DIR:-/root/.docker}` read-only into the Watchtower container as `/config` and sets `DOCKER_CONFIG=/config`. Watchtower reads `/config/config.json`, the same file `docker login ghcr.io` writes on the host. (Watchtower also accepts `REPO_USER` and `REPO_PASS`; the compose file does not set them, the mounted config is the supported path.) `bootstrap-node.sh` and `apply-update.sh` run `docker login` only when `GHCR_TOKEN` is set in the environment or `.env`. A node bootstrapped without a token never logs in, so `/root/.docker/config.json` has no `ghcr.io` entry, Watchtower pulls anonymously and gets `401 Unauthorized`. Its session line still says `failed=0` because the failed pull counts as skipped:

```text
level=warn msg="Digest retrieval failed, falling back to full pull" error="... status 401 Unauthorized"
level=warn msg="Could not pull image" error="... error from registry: unauthorized"
level=info msg="Update session completed" failed=0 scanned=0 skipped=1 updated=0
```

Docker creates the mount directory empty if it does not exist, and a login kept in a credential helper (`credsStore`) cannot be used inside the container. Both look the same from outside: no login.

**Check that a node updates.**
- `sh deploy/linux/registry-preflight.sh` says whether the image is public and whether the mounted config holds a `ghcr.io` login. It never prints a token.
- `sh deploy/linux/watchtower-health.sh` reads the Watchtower log of the last 72 h and prints a `WARNING` with the fix when it finds `unauthorized`, `401`, `denied`, `Could not pull image` or `scanned=0`. Both scripts always exit 0. `apply-update.sh` runs both before it recreates Watchtower, and `bootstrap-node.sh` runs the preflight. Recreating Watchtower starts a new log, so a node that was just updated shows "no update session yet" until 03:15.
- `python ops/probe.py all` includes the Watchtower check per node and ends with the list of nodes that cannot update.
- A healthy scheduled run has `scanned=1` (or more) and no `401`, for example `Update session completed failed=0 scanned=1 skipped=0 updated=0` (`updated=1` after a new release). On the node: `docker logs --since 48h powersvx-watchtower`.

**Fix 1: make the package public (owner action).** GitHub, the `powersvx` package, Package settings, Danger Zone, Change visibility, Public. Nodes then need no credentials and the warning goes away on the next check. Do this only if publishing the image is acceptable.

**Fix 2: give the node a token.** Create a GitHub personal access token (classic) with only the `read:packages` scope, or a fine-grained token with read access to the package. Then either:
1. put `GHCR_USER=<github user>` and `GHCR_TOKEN=<token>` in the node's `.env` and run `bash deploy/linux/apply-update.sh` (it logs in and recreates Watchtower), or
2. run `sudo docker login ghcr.io -u <github user>` on the node and paste the token when asked.

The login must land in the directory that is mounted: `/root/.docker` by default (`sudo` makes that the right one), or set `DOCKER_CONFIG_DIR` in `.env`. Recreate Watchtower afterwards so it re-reads the mount: `docker compose up -d --no-deps --force-recreate watchtower`. Keep the token only in `.env` (mode 600) and `config.json`; never in an issue, a commit or a chat.

**Rotate the token.** Create the new token, replace `GHCR_TOKEN` in each node's `.env` (or run `sudo docker login ghcr.io -u <github user>` again), run `apply-update.sh` or recreate Watchtower, run `watchtower-health.sh` after the next scheduled run (or `docker restart powersvx-watchtower` and read the log after 03:15), then delete the old token on GitHub. A revoked or expired token shows up as the same `401` warning.

## Deferred (enterprise)
- Raft HA / multi-node failover
- Redis L3 shared cache
- Full OIDC/SAML SSO
- True incremental IXFR journal
- Root-anchored DNSSEC chain-of-trust
- DHCP (only if LAN appliance is a product goal)
- Multi-tenancy
- HSM-backed DNSSEC keys
