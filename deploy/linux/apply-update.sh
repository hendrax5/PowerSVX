#!/bin/bash
# Run ON the PowerSVX server after SCP of update files.
# Usage:
#   cd /home/hendra/powersvx
#   bash deploy/linux/apply-update.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

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
export POWERSVX_UNBOUND_MODE="${POWERSVX_UNBOUND_MODE:-}"
export POWERSVX_UNBOUND_QUERYLOG="${POWERSVX_UNBOUND_QUERYLOG:-0}"
bash "$ROOT/deploy/linux/gen-unbound-conf.sh" "$ROOT/configs/unbound/unbound.conf"
if [ "$POWERSVX_DNS_DATAPLANE" = "dnsdist" ] || [ "$POWERSVX_DNS_DATAPLANE" = "cdb" ]; then
  chmod +x "$ROOT/deploy/linux/gen-dnsdist-conf.sh" || true
  bash "$ROOT/deploy/linux/gen-dnsdist-conf.sh" "$ROOT/configs/dnsdist/dnsdist.conf"
fi

echo "==> unbound RPZ memory guard (park huge zone if host too small)"
if [ -f "$ROOT/deploy/linux/unbound-rpz-guard.sh" ]; then
  chmod +x "$ROOT/deploy/linux/unbound-rpz-guard.sh" || true
  bash "$ROOT/deploy/linux/unbound-rpz-guard.sh" --park || true
fi

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
  "${COMPOSE[@]}" up -d --no-deps --force-recreate unbound dnsdist powersvx
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

echo "==> readiness (port 53 answers)"
if ! bash "$ROOT/deploy/linux/dns-ready.sh" -w "${POWERSVX_READY_WAIT:-90}" -u invalid; then
  echo "update applied but port 53 is not answering" >&2
  exit 1
fi
echo "done."
