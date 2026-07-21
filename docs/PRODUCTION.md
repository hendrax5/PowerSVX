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

## Conditional forwarders
- Global `[resolver] forwarders` plus optional `[[resolver.forward_zones]]` (`zone` + `forwarders`) for longest-suffix routing (stub/conditional). Editable in Settings.

## TLS (DoT / DoH / DoH3 / DoQ)
- Minimum TLS 1.3 for encrypted DNS listeners.
- Place certs in `certs/` (`cert_file` / `key_file` in TOML).

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
- Multi-tenancy
- HSM-backed DNSSEC keys
- Full NSEC3 + automated key rollover
