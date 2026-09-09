# Hermes — PowerSVX deploy / update

Read **`ops/inventory.local.yaml`** first. Match the user’s host by `name`, `ip`, or `aliases` (e.g. “70.254” → `isehat2`). Use that row’s SSH + UI credentials. Never commit `inventory.local.yaml`. Never print passwords in chat unless the user asks.

## Architecture (v1.6.3+ dnsdist)

**Production default:** **dnsdist** owns public `:53` with a **CDB blocklist** (full Kominfo AXFR, mmap). **Unbound** recurses only on `127.0.0.1:5353` (no huge RPZ). PowerSVX is control-plane (UI/API `:5380`, AXFR→CDB sync, banks whitelist, optional auth `:5354`).

```
Client → dnsdist :53
         ├─ bank SuffixMatchNode → Unbound :5353
         ├─ CDB hit (A/AAAA) → spoof 139.255.196.196 / ::
         └─ miss → Unbound :5353
PowerSVX → AXFR/hosts → data/blocklist/domains.cdb (+ banks.whitelist)
```

Env: `POWERSVX_DNS_DATAPLANE=dnsdist` (compose host default).

Legacy: `POWERSVX_DNS_DATAPLANE=unbound` puts Unbound on `:53` + RPZ (partial cap on ≤12 GiB). Stop dnsdist before that mode.

## When the user says “deploy” or “update”

Default target if unspecified: **isehat2 / 103.172.70.254**.

1. Resolve host from inventory.
2. Sync changed files to `remote_dir` (SCP) **or** `git pull` on the server.
3. `chmod +x deploy/linux/*.sh`
4. `export POWERSVX_DNS_DATAPLANE=dnsdist`
5. Prefer one-shot: `bash deploy/linux/apply-update.sh` (gens Unbound+dnsdist, builds powersvx, recreates unbound/dnsdist/powersvx).
6. Or manually:
   ```bash
   export POWERSVX_DNS_DATAPLANE=dnsdist
   bash deploy/linux/gen-unbound-conf.sh
   bash deploy/linux/gen-dnsdist-conf.sh
   eval "$(deploy/linux/calc-mem-env.sh)"
   export GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
   export BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   export POWERSVX_VERSION=1.6.2 GOGC=50
   docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml build powersvx
   docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml \
     up -d --no-deps --force-recreate unbound dnsdist powersvx
   ```
7. Verify:
   - `dig @127.0.0.1 -p 53 example.com` → NOERROR (**dnsdist → Unbound**)
   - known blocked name → `139.255.196.196`
   - bank apex (e.g. `bca.co.id`) → real A (whitelist)
   - `GET http://127.0.0.1:5380/api/v1/health` → `engine=dnsdist-cdb`
   - `ss -ulnp | grep ':53 '` → dnsdist; Unbound on `:5353`
   - MemAvailable / Recv-Q healthy (no Unbound RPZ thrash)

## Hard rules

- Host networking. Do not switch to bridge compose on these VPS.
- Do **not** `chown -R` on `data/postgres` (uid **70**).
- **Do not put Go PowerSVX back on public `:53`** in production.
- CDB holds the **full** AXFR list (no 1.5M Unbound RPZ cap). Banks filtered from CDB + dnsdist SMN.
- Keep Unbound RPZ zonefiles minimal when on dnsdist (API writes SOA stubs).
- Keep `POWERSVX_UNBOUND_QUERYLOG=0`.
- Dataplane: PowerSVX `POWERSVX_MEM_PERCENT` defaults to **30%**.
- Query log (Go edge) stays off (`POWERSVX_DISABLE_QUERY_LOG=1`).

## Incident lessons (JLA 2026-09-05)

| Symptom | Cause |
|---------|--------|
| Dig timeout, Recv-Q ~2M on `:53` | Unbound wedged under RAM pressure + optional query logging |
| Recreate Unbound “never finishes” | Loading 370 MB / 9.5M RPZ into ~11 GiB host → swap thrash |
| Disk 100% | Unbound `log-queries` + Docker image buildup |

**Recovery (legacy Unbound RPZ):** park huge zone → start empty → dig OK. **Preferred fix:** cut over to **dnsdist+CDB** (this architecture).

## Phrases → action

| User says | Do |
|-----------|----|
| deploy / update ke 70.254 / isehat2 | inventory → isehat2, steps above |
| deploy ke semua | loop `hosts` with `role: production` |
| cek status | health + dig :53 + docker ps + Recv-Q, no rebuild |
