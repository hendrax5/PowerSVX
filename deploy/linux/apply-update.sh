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

echo "==> install disk-guard cron (80%)"
sudo install -m 755 "$ROOT/deploy/linux/disk-guard.sh" /usr/local/sbin/powersvx-disk-guard
echo "POWERSVX_DIR=$ROOT" | sudo tee /etc/default/powersvx-disk-guard >/dev/null
echo "15 * * * * root . /etc/default/powersvx-disk-guard 2>/dev/null; /usr/local/sbin/powersvx-disk-guard" | sudo tee /etc/cron.d/powersvx-disk-guard >/dev/null
sudo POWERSVX_DIR="$ROOT" /usr/local/sbin/powersvx-disk-guard || true

echo "==> generate Unbound conf from host RAM/CPU"
bash "$ROOT/deploy/linux/gen-unbound-conf.sh" "$ROOT/configs/unbound/unbound.conf"

echo "==> recreate stack (logging limits + retention)"
export GIT_COMMIT="${GIT_COMMIT:-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
export BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export POWERSVX_VERSION="${POWERSVX_VERSION:-1.6.0}"
echo "build stamp VERSION=$POWERSVX_VERSION GIT_COMMIT=$GIT_COMMIT"
# Percent-based Docker mem_limit (default 40% of host RAM ≈ 4GiB soft on 11GB).
if [ -f "$ROOT/deploy/linux/calc-mem-env.sh" ]; then
  # shellcheck disable=SC1091
  eval "$("$ROOT/deploy/linux/calc-mem-env.sh")"
  export POWERSVX_MEM_LIMIT GOMEMLIMIT POWERSVX_MEM_PERCENT
fi
# Prefer short blip: rebuild powersvx + recreate unbound/powersvx only (not postgres).
COMPOSE=(docker compose -f docker-compose.yml)
if docker inspect powersvx --format '{{.HostConfig.NetworkMode}}' 2>/dev/null | grep -q host; then
  echo "detected host networking"
  COMPOSE+=(-f deploy/linux/docker-compose.host.yml)
elif [ -f "$ROOT/deploy/linux/docker-compose.linux.yml" ]; then
  COMPOSE+=(-f deploy/linux/docker-compose.linux.yml)
fi
"${COMPOSE[@]}" build powersvx
"${COMPOSE[@]}" up -d --no-deps --force-recreate unbound powersvx

echo "==> status"
docker ps --format 'table {{.Names}}\t{{.Status}}' | head -20
df -h / | tail -1
echo "done."
