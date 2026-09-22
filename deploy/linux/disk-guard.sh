#!/bin/bash
# Keep host disk usage under a threshold (default 80%), and always cap query_logs size.
# Fleet standard (all PowerSVX hosts):
#   - journald SystemMaxUse=1G (persistent drop-in)
#   - prune unused Docker images + build cache when disk is high
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
#   JOURNAL_MAX=1G          # journald SystemMaxUse + vacuum target
#   QUERY_LOG_MAX_MB=5120   # hard cap for query_logs (table+indexes)
#   PG_PASSWORD=...   (or load from $POWERSVX_DIR/.env)

set -euo pipefail

THRESHOLD="${DISK_GUARD_PCT:-80}"
MOUNT="${DISK_GUARD_PATH:-/}"
ROOT_DIR="${POWERSVX_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
QUERY_LOG_MAX_MB="${QUERY_LOG_MAX_MB:-5120}"
JOURNAL_MAX="${JOURNAL_MAX:-1G}"

pct() {
  df -P "$MOUNT" 2>/dev/null | awk 'NR==2 { gsub(/%/,"",$5); print $5 }'
}

load_env() {
  # shellcheck disable=SC1091
  if [ -f "$ROOT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$ROOT_DIR/.env"
    set +a
  fi
}

purge_query_logs_over_size() {
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx powersvx-postgres; then
    return 0
  fi
  load_env
  PASS="${PG_PASSWORD:-PowerSVXDevPass}"
  MAX_BYTES=$((QUERY_LOG_MAX_MB * 1024 * 1024))
  SIZE=$(docker exec -e PGPASSWORD="$PASS" powersvx-postgres \
    psql -U PowerSVX -d PowerSVX -Atc "SELECT pg_total_relation_size('query_logs');" 2>/dev/null || echo 0)
  if ! [[ "$SIZE" =~ ^[0-9]+$ ]]; then
    return 0
  fi
  if [ "$SIZE" -le "$MAX_BYTES" ]; then
    echo "disk-guard: query_logs ${SIZE} bytes <= ${QUERY_LOG_MAX_MB}MB — ok"
    return 0
  fi
  echo "disk-guard: query_logs ${SIZE} bytes > ${QUERY_LOG_MAX_MB}MB — trimming oldest…"
  TARGET=$((MAX_BYTES * 90 / 100))
  for _ in $(seq 1 40); do
    SIZE=$(docker exec -e PGPASSWORD="$PASS" powersvx-postgres \
      psql -U PowerSVX -d PowerSVX -Atc "SELECT pg_total_relation_size('query_logs');" 2>/dev/null || echo 0)
    if ! [[ "$SIZE" =~ ^[0-9]+$ ]] || [ "$SIZE" -le "$TARGET" ]; then
      break
    fi
    docker exec -e PGPASSWORD="$PASS" powersvx-postgres \
      psql -U PowerSVX -d PowerSVX -v ON_ERROR_STOP=1 -c \
      "DELETE FROM query_logs WHERE ctid IN (
         SELECT ctid FROM query_logs ORDER BY timestamp ASC, id ASC LIMIT 100000
       );" >/dev/null 2>&1 || break
  done
  docker exec -e PGPASSWORD="$PASS" powersvx-postgres \
    psql -U PowerSVX -d PowerSVX -c "VACUUM (ANALYZE) query_logs;" >/dev/null 2>&1 || true
  AFTER=$(docker exec -e PGPASSWORD="$PASS" powersvx-postgres \
    psql -U PowerSVX -d PowerSVX -Atc "SELECT pg_total_relation_size('query_logs');" 2>/dev/null || echo "?")
  echo "disk-guard: query_logs now ${AFTER} bytes"
}

ensure_journald_cap() {
  # Persistent fleet standard: never let journals grow unbounded.
  if [ "$(id -u)" -ne 0 ]; then
    echo "disk-guard: journald cap skipped (need root)" >&2
    return 0
  fi
  if ! command -v journalctl >/dev/null 2>&1; then
    return 0
  fi
  conf_dir=/etc/systemd/journald.conf.d
  conf_file="${conf_dir}/powersvx-size.conf"
  mkdir -p "$conf_dir"
  cat >"$conf_file" <<EOF
[Journal]
SystemMaxUse=${JOURNAL_MAX}
SystemKeepFree=500M
MaxRetentionSec=14day
EOF
  chmod 644 "$conf_file"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart systemd-journald >/dev/null 2>&1 || true
  fi
  journalctl --vacuum-size="$JOURNAL_MAX" >/dev/null 2>&1 || true
  echo "disk-guard: journald SystemMaxUse=${JOURNAL_MAX}"
}

prune_docker_light() {
  # Safe anytime: dangling images + old build cache only.
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  docker image prune -f >/dev/null 2>&1 || true
  docker builder prune -f --filter until=168h >/dev/null 2>&1 || true
}

prune_docker_hard() {
  # When disk is high: drop ALL unused images + entire build cache.
  # Running containers keep their images.
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  for id in $(docker ps -aq 2>/dev/null || true); do
    logpath=$(docker inspect --format='{{.LogPath}}' "$id" 2>/dev/null || true)
    if [ -n "${logpath:-}" ] && [ -f "$logpath" ]; then
      size=$(stat -c%s "$logpath" 2>/dev/null || echo 0)
      if [ "${size:-0}" -gt 20971520 ]; then
        : > "$logpath" || true
        echo "disk-guard: truncated docker log $id (${size} bytes)"
      fi
    fi
  done
  docker image prune -af >/dev/null 2>&1 || true
  docker builder prune -af >/dev/null 2>&1 || true
  echo "disk-guard: docker unused images + build cache pruned"
}

# Always enforce journald 1G + query_log size (even when disk % is fine).
ensure_journald_cap
purge_query_logs_over_size
prune_docker_light

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

# 1) Aggressive Docker reclaim
prune_docker_hard

# 2) Re-vacuum journal to cap (idempotent)
if command -v journalctl >/dev/null 2>&1; then
  journalctl --vacuum-size="$JOURNAL_MAX" >/dev/null 2>&1 || true
fi

# 3) Aggressive age purge when disk is high (keep 1 day)
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx powersvx-postgres; then
  load_env
  PASS="${PG_PASSWORD:-PowerSVXDevPass}"
  docker exec -e PGPASSWORD="$PASS" powersvx-postgres \
    psql -U PowerSVX -d PowerSVX -v ON_ERROR_STOP=1 -c \
    "DELETE FROM query_logs WHERE ctid IN (
       SELECT ctid FROM query_logs WHERE timestamp < NOW() - INTERVAL '1 day' LIMIT 200000
     ); VACUUM (ANALYZE) query_logs;" \
    >/dev/null 2>&1 && echo "disk-guard: purged query_logs older than 1 day (batch)" || \
    echo "disk-guard: query_logs age purge skipped (db busy/recovering)" >&2
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
