# Hermes — PowerSVX deploy / update

Read **`ops/inventory.local.yaml`** first. Match the user’s host by `name`, `ip`, or `aliases` (e.g. “70.254” → `isehat2`). Use that row’s SSH + UI credentials. Never commit `inventory.local.yaml`. Never print passwords in chat unless the user asks.

## When the user says “deploy” or “update”

Default target if unspecified: **isehat2 / 103.172.70.254**.

1. Resolve host from inventory.
2. Sync the changed files to `remote_dir` (SCP) **or** `git pull` on the server if the tree is a clone of `git_remote`.
3. `chmod +x deploy/linux/*.sh`
4. `bash deploy/linux/gen-unbound-conf.sh configs/unbound/unbound.conf` (sizes Unbound from RAM/CPU).
5. `eval "$(deploy/linux/calc-mem-env.sh)"` then export `POWERSVX_MEM_LIMIT` `GOMEMLIMIT`.
   Stamp the UI version from git (so Dashboard shows `v1.6.0 · <sha>`):
   `export GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)`
   `export BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)`
   `export POWERSVX_VERSION=1.6.0`
6. Build + recreate **only** `compose.recreate` (unbound then powersvx). Do **not** recreate postgres/grafana unless asked.
   ```bash
   docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml \
     build powersvx
   docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml \
     up -d --no-deps --force-recreate unbound powersvx
   ```
7. Verify:
   - `GET http://127.0.0.1:5380/api/v1/health` → `healthy`
   - settings: `resolver_mode=forward`, `forwarders=["127.0.0.1:5353"]`
   - `dig @127.0.0.1 -p 53 example.com` and `dig @127.0.0.1 -p 5353 example.com` → NOERROR
   - docker logs: `autosize` + Unbound healthy

## Hard rules

- Host networking. Do not switch to bridge compose on these VPS.
- Do **not** `chown -R` on `data/postgres` (uid **70**).
- Keep Unbound as default resolver; recursive Go is lab-only.
- Prefer short DNS blip (recreate `powersvx` only) over full stack restart.
- Query log stays sampled/off under load.

## Phrases → action

| User says | Do |
|-----------|----|
| deploy / update ke 70.254 / isehat2 | inventory → isehat2, steps above |
| deploy ke semua | loop `hosts` with `role: production` |
| cek status | health + settings + docker ps + conntrack, no rebuild |
