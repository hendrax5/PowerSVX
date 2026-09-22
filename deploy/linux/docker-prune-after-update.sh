#!/bin/bash
# Prune Docker build cache and unused images after install/update.
# Safe: does NOT remove named volumes (postgres/data).
#
# Usage (on host, as root or docker-capable user):
#   bash deploy/linux/docker-prune-after-update.sh
set -euo pipefail

echo "==> docker prune (post install/update)"
df -h / | tail -1 || true

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found — skip prune"
  exit 0
fi

# BuildKit/cache from compose builds
docker builder prune -af 2>/dev/null || true
# Unused images (old powersvx layers after recreate)
docker image prune -af 2>/dev/null || true
# Stopped containers / unused networks only
docker container prune -f 2>/dev/null || true
docker network prune -f 2>/dev/null || true

echo "==> docker disk after prune"
docker system df 2>/dev/null || true
df -h / | tail -1 || true
echo "docker prune done."
