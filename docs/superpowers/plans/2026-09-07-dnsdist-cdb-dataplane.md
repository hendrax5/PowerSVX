# dnsdist + CDB Blocklist Dataplane Implementation Plan

**Goal:** Put Kominfo/TrustPositif filtering in **dnsdist + CDB** (full list, low RAM) while Unbound only recurses on localhost; PowerSVX stays control-plane (AXFR/hosts sync, banks whitelist, UI).

**Architecture:**
```
Client → dnsdist :53
         ├─ bank SuffixMatchNode → Unbound :5353
         ├─ CDB hit → Spoof 139.255.196.196
         └─ miss → Unbound :5353
PowerSVX → AXFR/hosts → domains.txt → CDB → reload dnsdist
```

## Status (JLA / isehat2 — 2026-09-07)

**Deployed and verified:**
- `POWERSVX_DNS_DATAPLANE=dnsdist`
- CDB ~9.6M entries (~445MB mmap); MemAvailable ~9–10 GiB
- dig: google OK, banks OK, blocked → `139.255.196.196`
- health: `engine=dnsdist-cdb`

**Gotchas fixed during cutover:**
- docker image ENTRYPOINT is already `dnsdist` — `command` must NOT repeat `dnsdist`
- bind `:53` needs `user: "0:0"` (+ `NET_BIND_SERVICE`)
- `setACL({"0.0.0.0/0","::/0"})` for public ISP queries
- raise `ulimits.nofile` (≥65535)

## File map

| Path | Role |
|------|------|
| `internal/blockcdb/` | Write domains + build `domains.cdb` |
| `internal/config/dataplane.go` | `POWERSVX_DNS_DATAPLANE=dnsdist` |
| `internal/api/cdb_sync.go` | AXFR/hosts → CDB sync |
| `deploy/linux/gen-dnsdist-conf.sh` | Render dnsdist.conf |
| `deploy/linux/gen-unbound-conf.sh` | `dnsdist` → backend :5353 |
| `deploy/linux/docker-compose.host.yml` | dnsdist + Unbound overlay |
| `ops/HERMES.md` / `docs/PRODUCTION.md` | Ops docs |

### Checklist
- [x] Dataplane flag `dnsdist`
- [x] CDB writer + tests
- [x] AXFR/hosts → full CDB sync + banks filter
- [x] Compose + gen scripts + apply-update
- [x] Deploy & verify on JLA

### Rollback
`POWERSVX_DNS_DATAPLANE=unbound`, stop dnsdist, regenerate Unbound on `:53`.
