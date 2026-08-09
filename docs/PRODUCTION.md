# PowerSVX production notes (Raft clustering deferred)

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
- `[transfer] allow_axfr = true` enables outbound zone transfer.
- **IXFR is answered as full AXFR** (no incremental journal). Clients that request IXFR still get a complete zone dump. True delta-IXFR is deferred.
- Secondary (slave) zones: configure via API/UI (`data/secondary-zones.json`) with `masters`; inbound DNS NOTIFY triggers AXFR pull; periodic refresh uses SOA/refresh interval.
- `require_tsig = true` (default) needs a valid TSIG on the transfer.
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
- Enable via zone meta `dnssec_enabled` (DB) or `POST /api/v1/zones/{name}/dnssec`.
- Keys stored under `data/dnssec/<zone>/` (KSK+ZSK, ECDSAP256SHA256).
- Answers signed when client sets DO; DNSKEY queries return keys + RRSIG.
- NXDOMAIN includes a simplified NSEC + RRSIG when DO is set.
- Publish the returned **DS** at the parent / registrar.
- Full NSEC3 / key rollover / HSM still deferred.

## AXFR sync (Tools)
- Settings → Tools → **AXFR**. Two independent directions:
  - **Outbound secondary (NOTIFY):** default **disabled**. Default sources Kominfo secondaries `182.23.79.202` / `139.255.196.202` (editable; also `[kominfo_sync] targets` / `axfr_sync_targets`). When enabled those IPs may AXFR/IXFR without global `allow_axfr` / TSIG; zone changes send NOTIFY. **Sync now** walks all zones (NOTIFY → SOA check). Persisted in `runtime-settings.json` as `axfr_sync_enabled` + `axfr_sync_targets` (legacy `kominfo_sync_enabled` still accepted).
  - **Filter feeds (slave AXFR):** PowerSVX as slave pulls a configured zone via AXFR from masters; owner names are stored **relative to the zone apex** (so `evil.com.trustpositifkominfo.` → `evil.com.`) and enter the RPZ engine with an action (`nxdomain` / `nodata` / `pass` / `redirect` / `cname`). First sync is full AXFR; later refreshes use **IXFR** when the SOA serial advances (fallback to AXFR). Serials live in `data/rpz-axfr-state.json`. Default **`axfr_update_interval = 86400`** (24h), independent of hosts `update_interval`. Inbound NOTIFY for a matching zone triggers an AXFR/IXFR refresh without re-downloading hosts feeds. Policies use `format=axfr` with `zone` + `masters` in `data/rpz-policies.json`. HTTP hosts feeds remain under Tools → RPZ.

## GeoDNS
- Uses MaxMind-compatible MMDB (`[geodns] database_path`).
- **Docker default:** DB-IP Country Lite (`/data/dbip-country-lite.mmdb`), auto-downloaded by `deploy/docker/entrypoint.sh` on start if missing or older than ~35 days (CC BY 4.0 — attribute [DB-IP](https://db-ip.com)).
- Skip with `GEODB_AUTO_DOWNLOAD=0`. Override path with `GEODB_PATH`.
- Lookup uses City DB when present, otherwise Country DB.

## Query logs
- Requires PostgreSQL + `query_log_enabled = true`.
- `query_log_mask_ip = true` stores /24 (IPv4) or /48 (IPv6).
- `query_log_retention_days` runs an hourly purge job.

## Reload
- `SIGHUP` / `systemctl reload powersvx` reloads `runtime-settings.json` flags, query ACL, and plugins.
- Data directory: `--data-dir` (default `./data`; Linux package uses `/var/lib/powersvx`).

## Linux deploy
- See `deploy/linux/README.md` — systemd unit, `configs/powersvx.linux.toml`, `install.sh`, Docker override.

## Deferred (enterprise)
- Raft HA / multi-node failover
- Redis L3 shared cache
- Full OIDC/SAML SSO
- True incremental IXFR journal
- Root-anchored DNSSEC chain-of-trust
- DHCP (only if LAN appliance is a product goal)
- Multi-tenancy
- HSM-backed DNSSEC keys
- Full NSEC3 + automated key rollover
