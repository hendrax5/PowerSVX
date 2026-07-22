#!/bin/bash
# Keep host disk usage under a threshold (default 80%).
# Safe cleanups: Docker json logs, unused images, old query_logs, journal.
#
# Install (hourly):
#   sudo install -m 755 deploy/linux/disk-guard.sh /usr/local/sbin/powersvx-disk-guard
#   echo '15 * * * * root /usr/local/sbin/powersvx-disk-guard' | sudo tee /etc/cron.d/powersvx-disk-guard
#
# Env overrides:
#   DISK_GUARD_PCT=80
#   DISK_GUARD_PATH=/
#   POWERSVX_DIR=/home/hendra/powersvx
#   PG_PASSWORD=...   (or load from $POWERSVX_DIR/.env)

set -euo pipefail

THRESHOLD="${DISK_GUARD_PCT:-80}"
MOUNT="${DISK_GUARD_PATH:-/}"
ROOT_DIR="${POWERSVX_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"

pct() {
  df -P "$MOUNT" 2>/dev/null | awk 'NR==2 { gsub(/%/,"",$5); print $5 }'
}

USED=$(pct || echo 0)
if ! [[ "$USED" =~ ^[0-9]+$ ]]; then
  echo "disk-guard: cannot read usage for $MOUNT" >&2
  exit 1
fi

if [ "$USED" -lt "$THRESHOLD" ]; then
  echo "disk-guard: ${USED}% < ${THRESHOLD}% — ok"
  exit 0
fi

echo "disk-guard: ${USED}% >= ${THRESHOLD}% — cleaning…"

# 1) Cap / truncate Docker container logs
if command -v docker >/dev/null 2>&1; then
  for id in $(docker ps -aq 2>/dev/null || true); do
    logpath=$(docker inspect --format='{{.LogPath}}' "$id" 2>/dev/null || true)
    if [ -n "${logpath:-}" ] && [ -f "$logpath" ]; then
      # truncate large logs (>20MB)
      size=$(stat -c%s "$logpath" 2>/dev/null || echo 0)
      if [ "${size:-0}" -gt 20971520 ]; then
        : > "$logpath" || true
        echo "disk-guard: truncated docker log $id (${size} bytes)"
      fi
    fi
  done
  docker image prune -f >/dev/null 2>&1 || true
  docker builder prune -f --filter until=72h >/dev/null 2>&1 || true
fi

# 2) Journal (if present)
if command -v journalctl >/dev/null 2>&1; then
  journalctl --vacuum-size=200M >/dev/null 2>&1 || true
fi

# 3) Aggressive query_log purge when disk is high (keep 2 days)
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx powersvx-postgres; then
  # shellcheck disable=SC1091
  if [ -f "$ROOT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$ROOT_DIR/.env"
    set +a
  fi
  PASS="${PG_PASSWORD:-PowerSVXDevPass}"
  docker exec -e PGPASSWORD="$PASS" powersvx-postgres \
    psql -U PowerSVX -d PowerSVX -v ON_ERROR_STOP=1 -c \
    "DELETE FROM query_logs WHERE timestamp < NOW() - INTERVAL '2 days'; VACUUM (VERBOSE, ANALYZE) query_logs;" \
    >/dev/null 2>&1 && echo "disk-guard: purged query_logs older than 2 days" || \
    echo "disk-guard: query_logs purge skipped (db busy/recovering)" >&2
fi

# 4) Apt cache (Debian/Ubuntu hosts)
if command -v apt-get >/dev/null 2>&1; then
  apt-get clean >/dev/null 2>&1 || true
fi

AFTER=$(pct || echo "$USED")
echo "disk-guard: done — was ${USED}%, now ${AFTER}%"
if [ "$AFTER" -ge "$THRESHOLD" ]; then
  echo "disk-guard: still >= ${THRESHOLD}% — free space manually (du -xh / | sort -h | tail)" >&2
  exit 2
fi
