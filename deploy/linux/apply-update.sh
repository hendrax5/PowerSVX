#!/bin/bash
# Run ON the PowerSVX server after SCP of update files.
# Usage:
#   cd /home/hendra/powersvx
#   bash deploy/linux/apply-update.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Stop before touching anything when this node is on a Dataplane mode being removed.
sh "$ROOT/deploy/linux/dataplane-guard.sh" "$ROOT" || exit 1

# Only warns; never removes anything and never fails the update.
sh "$ROOT/deploy/linux/tproxy-leftover.sh" || true

echo "==> disk free"
df -h / | tail -1

if [ -f "$ROOT/powersvx-disk-guard.bundle" ]; then
  echo "==> importing git bundle"
  if git pull "$ROOT/powersvx-disk-guard.bundle" HEAD 2>/dev/null; then
    echo "bundle pulled"
  elif git fetch "$ROOT/powersvx-disk-guard.bundle" HEAD:refs/bundles/disk-guard && git merge --ff-only refs/bundles/disk-guard; then
    echo "bundle merged"
  else
    echo "bundle import failed — will try tarball / existing tree" >&2
  fi
fi

if [ -f "$ROOT/powersvx-disk-guard-files.tgz" ]; then
  echo "==> extracting file tarball"
  tar -xzf "$ROOT/powersvx-disk-guard-files.tgz" -C "$ROOT"
fi

git status -sb 2>/dev/null || true
git log -1 --oneline 2>/dev/null || true

if [ ! -f "$ROOT/deploy/linux/disk-guard.sh" ]; then
  echo "missing deploy/linux/disk-guard.sh — abort" >&2
  exit 1
fi

echo "==> install disk-guard cron (journald max 1G, clean at 80%)"
sudo install -m 755 "$ROOT/deploy/linux/disk-guard.sh" /usr/local/sbin/powersvx-disk-guard
echo "POWERSVX_DIR=$ROOT" | sudo tee /etc/default/powersvx-disk-guard >/dev/null
echo "15 * * * * root . /etc/default/powersvx-disk-guard 2>/dev/null; /usr/local/sbin/powersvx-disk-guard" | sudo tee /etc/cron.d/powersvx-disk-guard >/dev/null
sudo POWERSVX_DIR="$ROOT" /usr/local/sbin/powersvx-disk-guard || true

echo "==> apply OS & kernel hardening"
if [ -f "$ROOT/deploy/linux/os-hardening.sh" ]; then
  chmod +x "$ROOT/deploy/linux/os-hardening.sh" 2>/dev/null || true
  sudo bash "$ROOT/deploy/linux/os-hardening.sh" || true
fi

echo "==> generate Unbound + dnsdist conf"
export POWERSVX_DNS_DATAPLANE="${POWERSVX_DNS_DATAPLANE:-dnsdist}"
bash "$ROOT/deploy/linux/gen-unbound-conf.sh" "$ROOT/configs/unbound/unbound.conf"
if [ "$POWERSVX_DNS_DATAPLANE" = "dnsdist" ] || [ "$POWERSVX_DNS_DATAPLANE" = "cdb" ]; then
  chmod +x "$ROOT/deploy/linux/gen-dnsdist-conf.sh" || true
  # The dnsdist web password and API key live in .env: created there only when missing (never
  # printed), then exported so the generator writes what compose hands to the Control Plane.
  # A node that still has the old public defaults gets new values here; the order below
  # (Control Plane first, then the dnsdist configuration) is unchanged, see docs/PRODUCTION.md.
  sh "$ROOT/deploy/linux/ensure-dnsdist-credentials.sh" "$ROOT/.env"
  for k in POWERSVX_DNSDIST_WEB_PASSWORD POWERSVX_DNSDIST_API_KEY; do
    if [ -z "${!k:-}" ]; then
      export "$k=$(grep -E "^$k=" "$ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d "\"'\r")"
    fi
  done
  # Written beside the live file and moved into place only after the new Control Plane is up
  # (see below): a dnsdist that sends PROXY headers must never meet a Control Plane that
  # does not understand them.
  bash "$ROOT/deploy/linux/gen-dnsdist-conf.sh" "$ROOT/configs/dnsdist/dnsdist.conf.new"
fi

echo "==> check the Unbound configuration (before Unbound is recreated)"
bash "$ROOT/deploy/linux/check-unbound-conf.sh" "$ROOT" || exit 1

echo "==> recreate stack (logging limits + retention)"
export GIT_COMMIT="${GIT_COMMIT:-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
export BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export POWERSVX_VERSION="${POWERSVX_VERSION:-1.7.1}"
export GOGC="${GOGC:-50}"
echo "build stamp VERSION=$POWERSVX_VERSION GIT_COMMIT=$GIT_COMMIT DATAPLANE=$POWERSVX_DNS_DATAPLANE"
# Dataplane default mem_percent=30 via calc-mem-env (leave RAM for Unbound).
if [ -f "$ROOT/deploy/linux/calc-mem-env.sh" ]; then
  # shellcheck disable=SC1091
  eval "$("$ROOT/deploy/linux/calc-mem-env.sh")"
  export POWERSVX_MEM_LIMIT GOMEMLIMIT POWERSVX_MEM_PERCENT
fi
# Prefer short blip: rebuild/pull powersvx + recreate unbound/dnsdist/powersvx only (not postgres).
COMPOSE=(docker compose -f docker-compose.yml)
if docker inspect powersvx --format '{{.HostConfig.NetworkMode}}' 2>/dev/null | grep -q host; then
  echo "detected host networking"
  COMPOSE+=(-f deploy/linux/docker-compose.host.yml)
elif [ -f "$ROOT/deploy/linux/docker-compose.linux.yml" ]; then
  COMPOSE+=(-f deploy/linux/docker-compose.linux.yml)
fi
# POWERSVX_PROFILE=core (environment or .env) is the only thing that changes the stack here;
# unset means full, whatever the host memory.
PROFILE="$(sh "$ROOT/deploy/linux/select-profile.sh" -e)" || exit 1
if [ "$PROFILE" = "core" ]; then
  COMPOSE+=(-f deploy/linux/docker-compose.core.yml)
fi
if [ -z "${GHCR_TOKEN:-}" ] && [ -f "$ROOT/.env" ]; then
  GHCR_USER="${GHCR_USER:-$(grep -E '^GHCR_USER=' "$ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d "\"'\r" || true)}"
  GHCR_TOKEN="$(grep -E '^GHCR_TOKEN=' "$ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d "\"'\r" || true)"
fi
if [ -n "${GHCR_TOKEN:-}" ]; then
  echo "==> logging in to ghcr.io"
  printf '%s\n' "$GHCR_TOKEN" | docker login ghcr.io -u "${GHCR_USER:-hendrax5}" --password-stdin >/dev/null
fi
if [ "${POWERSVX_PULL_IMAGE:-0}" = "1" ]; then
  "${COMPOSE[@]}" pull powersvx || "${COMPOSE[@]}" build powersvx
else
  "${COMPOSE[@]}" build powersvx
fi
if [ "$POWERSVX_DNS_DATAPLANE" = "dnsdist" ] || [ "$POWERSVX_DNS_DATAPLANE" = "cdb" ]; then
  # 1. The new Control Plane first: with [server] proxy_protocol = "optional" it answers both the
  #    old dnsdist (plain queries) and the new one (PROXY headers).
  "${COMPOSE[@]}" up -d --no-deps --force-recreate powersvx
  echo "==> waiting for the new Control Plane before the dnsdist configuration changes"
  cp_up=0
  for _ in $(seq 1 60); do
    if curl -fsS -m 3 "http://127.0.0.1:${POWERSVX_API_PORT:-5380}/api/v1/health" >/dev/null 2>&1; then cp_up=1; break; fi
    sleep 2
  done
  if [ "$cp_up" != 1 ]; then
    echo "WARNING: the Control Plane did not answer /api/v1/health within 120 s; the dnsdist configuration was NOT replaced." >&2
    echo "The new configuration is configs/dnsdist/dnsdist.conf.new. Move it into place and recreate dnsdist once the Control Plane is healthy." >&2
    echo "The Control Plane already uses the dnsdist web credentials from .env, so until dnsdist is recreated its statistics and runtime-control calls are refused (DNS answering is not affected)." >&2
    exit 1
  fi
  # 2. Then the dnsdist configuration and the Dataplane containers.
  mv -f "$ROOT/configs/dnsdist/dnsdist.conf.new" "$ROOT/configs/dnsdist/dnsdist.conf"
  "${COMPOSE[@]}" up -d --no-deps --force-recreate unbound dnsdist
else
  "${COMPOSE[@]}" stop dnsdist 2>/dev/null || true
  "${COMPOSE[@]}" rm -f dnsdist 2>/dev/null || true
  "${COMPOSE[@]}" up -d --no-deps --force-recreate unbound powersvx
fi

if [ "$PROFILE" = "core" ]; then
  echo "==> auto-update (watchtower); Core Profile, removing Observability containers"
  "${COMPOSE[@]}" up -d --no-deps --force-recreate watchtower || true
  "${COMPOSE[@]}" rm -sf node-exporter prometheus grafana || true
else
  echo "==> metrics & auto-update stack (node-exporter + prometheus + grafana + watchtower)"
  "${COMPOSE[@]}" up -d --no-deps --force-recreate node-exporter prometheus grafana watchtower || true
fi

echo "==> prune docker build cache + unused images"
chmod +x "$ROOT/deploy/linux/docker-prune-after-update.sh" 2>/dev/null || true
bash "$ROOT/deploy/linux/docker-prune-after-update.sh" || true

echo "==> status"
docker ps --format 'table {{.Names}}\t{{.Status}}' | head -20
df -h / | tail -1

echo "==> readiness (port 53 answers, then a real name resolves by recursion)"
if ! bash "$ROOT/deploy/linux/dns-ready.sh" -w "${POWERSVX_READY_WAIT:-90}" -u invalid; then
  echo "update applied but port 53 is not answering" >&2
  exit 1
fi
if ! bash "$ROOT/deploy/linux/dns-ready.sh" -w "${POWERSVX_READY_WAIT:-90}" -r "${POWERSVX_READY_NAME:-example.com}"; then
  echo "update applied but recursion is not working (port 53 answers local names only)." >&2
  echo "Check: docker exec powersvx-unbound-1 unbound-control list_forwards ; docs/PRODUCTION.md, \"Unbound forwards to itself\"" >&2
  exit 1
fi
echo "done."
