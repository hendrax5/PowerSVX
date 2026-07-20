# PowerSVX production notes (Raft clustering deferred)

## Auth
- Set `auth_type = "token"` and `api_token` (or env `API_TOKEN`).
- Health (`/api/v1/health`) stays open; all other REST routes need `Authorization: Bearer <token>`.
- SSE may use `?token=` for EventSource.
- Process refuses to start if `auth_type=token` and token is empty.

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
- Publish the returned **DS** at the parent / registrar.
- NSEC/NSEC3 authenticated denial is not included yet.

## Query logs
- Requires PostgreSQL + `query_log_enabled = true`.
