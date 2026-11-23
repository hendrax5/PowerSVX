# Hermes — PowerSVX deploy / update

Read **`ops/inventory.local.yaml`** first. Match the user’s host by `name`, `ip`, or `aliases` (e.g. “70.254” → `isehat2`). Resolve passwords from **`ops/vault.local.yaml`** via `ssh_vault` / `admin_vault` (preferred) or legacy inline fields. Never commit `*.local.yaml`. Never print passwords in chat unless the user asks.

Copy templates if missing: `ops/inventory.example.yaml` → `inventory.local.yaml`, `ops/vault.example.yaml` → `vault.local.yaml`.

## Architecture (v1.7.0+ dnsdist)

**Production default:** **dnsdist** owns public `:53` with a **CDB blocklist** (full Kominfo AXFR/IXFR, mmap). **Unbound** recurses only on `127.0.0.1:5353` (no huge RPZ). PowerSVX is control-plane (UI/API `:5380`, AXFR/IXFR→CDB sync, banks whitelist, auth & slave zones `:5354`, `OpcodeNotify` routed by dnsdist to `:5354`).

```
Client → dnsdist :53
         ├─ bank SuffixMatchNode → Unbound :5353
         ├─ OpcodeNotify → PowerSVX :5354
         ├─ CDB hit (A/AAAA) → spoof 139.255.196.196 / ::
         └─ miss → Unbound :5353
PowerSVX → AXFR/IXFR/hosts → data/blocklist/domains.cdb (+ banks.whitelist + authzones.cdb)
```

Env: `POWERSVX_DNS_DATAPLANE=dnsdist` (compose host default).

`POWERSVX_DNS_DATAPLANE=unbound` (Unbound on `:53` + RPZ) was removed; a node still set to it is refused at update and at start. See `docs/PRODUCTION.md`.

## When the user says “install”, “bootstrap”, or “fresh deploy”

For a **brand-new host** (or fresh VPS):
1. Resolve host from inventory (`ops/inventory.local.yaml`).
2. SSH to the server and clone/sync repo to `/home/hendra/powersvx`.
3. Run the one-shot turnkey bootstrap as root:
   ```bash
   sudo bash deploy/linux/bootstrap-node.sh
   ```
   *This automatically installs Docker, applies kernel `NOTRACK` + 3M conntrack hardening, creates random `.env` secrets, auto-sizes Unbound/Dnsdist configs, and spins up the full stack including Grafana on port 3000.*

## When the user says “deploy” or “update” (Existing Nodes)

Default target if unspecified: **isehat2 / 103.172.70.254**.

1. Resolve host from inventory.
2. Sync changed files to `remote_dir` (SCP) **or** `git pull` on the server.
3. `chmod +x deploy/linux/*.sh`
4. `export POWERSVX_DNS_DATAPLANE=dnsdist`
5. Prefer one-shot: `bash deploy/linux/apply-update.sh` (gens Unbound+dnsdist, builds powersvx, recreates unbound/dnsdist/powersvx, starts grafana/prometheus, then **prunes Docker build cache + unused images**).
6. Or manually:
   ```bash
   export POWERSVX_DNS_DATAPLANE=dnsdist
   bash deploy/linux/gen-unbound-conf.sh
   bash deploy/linux/gen-dnsdist-conf.sh
   eval "$(deploy/linux/calc-mem-env.sh)"
   export GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
   export BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   export POWERSVX_VERSION=1.7.1 GOGC=50
   docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml build powersvx
   docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml \
     up -d --no-deps --force-recreate unbound dnsdist powersvx node-exporter prometheus grafana
   bash deploy/linux/docker-prune-after-update.sh
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
- Dataplane: PowerSVX `POWERSVX_MEM_PERCENT` defaults to **30%**.
- Query log sampling is off by default (see "Sampled query log" in `deploy/linux/README.md`).

## Host hygiene (fleet standard)

Every production host must run `deploy/linux/disk-guard.sh` hourly (installed by `apply-update.sh`):

| Cap | Value |
|-----|--------|
| **journald** | `SystemMaxUse=1G` (`/etc/systemd/journald.conf.d/powersvx-size.conf`) |
| Disk trigger | clean when ≥ **80%** |
| Over threshold | `docker image prune -af` + `docker builder prune -af` + truncate large container logs |

Always-on (even under 80%): journald drop-in + vacuum to 1G, light dangling-image prune, query_logs size cap.

```bash
# one host
sudo bash deploy/linux/disk-guard.sh
# or after deploy
bash deploy/linux/apply-update.sh   # installs cron + runs once
```

Phrase: **“hygiene semua” / “prune fleet”** → loop inventory hosts with SSH creds and run `disk-guard.sh` (root).

## Default filter (TrustPositif AXFR) + GitHub seed

- Default policy: `trustpositifkominfo` AXFR from `182.23.79.202:53` / `139.255.196.202:53` (enabled). UI can **Disable** without deleting.
- **First boot:** if `domains.cdb` empty/tiny, bootstrap from GitHub Release  
  `https://github.com/hendrax5/PowerSVX/releases/latest/download/blocklist-seed.tgz`  
  (`POWERSVX_FILTER_SEED_URL`; set `off` to skip). Then IXFR/SOA-skip vs Komdigi — no full AXFR unless seed missing.
- **Publish seed from JMG** (after sync):  
  `bash deploy/linux/publish-filter-seed.sh` (needs `gh` + API token).  
  Or `GET /api/v1/blocklist/seed` (auth) → upload asset manually.
- **AXFR fail:** keep last-good CDB; health `filter sync failed; serving last CDB`. DNS resolve stays up (dnsdist→Unbound).
- dnsdist backend health: `maxCheckFailures=5`, `checkTimeout=2000` in `gen-dnsdist-conf.sh`.
- Policy file lives in Docker volume `/data/rpz-policies.json` on some hosts (not only host `data/`).

## Incident lessons (JLA 2026-09-05)

| Symptom | Cause |
|---------|--------|
| Dig timeout, Recv-Q ~2M on `:53` | Unbound wedged under RAM pressure + optional query logging |
| Recreate Unbound “never finishes” | Loading 370 MB / 9.5M RPZ into ~11 GiB host → swap thrash |
| Disk 100% | Unbound `log-queries` + Docker image buildup |

**Recovery (a node still on the removed Unbound RPZ mode):** cut over to **dnsdist+CDB** (this architecture); see `docs/PRODUCTION.md`.

## Phrases → action

| User says | Do |
|-----------|----|
| deploy / update ke 70.254 / isehat2 | inventory → isehat2, steps above |
| deploy ke semua | loop `hosts` with `role: production` |
| cek status | health + dig :53 + docker ps + Recv-Q, no rebuild |
| hygiene / prune fleet / disk | install+run `disk-guard.sh` (journal 1G + docker prune) on all SSH-ready hosts |
