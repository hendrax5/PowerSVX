#!/bin/sh
# Ensure data dirs exist; optionally fetch free DB-IP Country Lite (CC BY 4.0).
# Run as root so privileged ports (53/853/443) bind reliably.
set -e
mkdir -p /data/cache /var/log/PowerSVX /etc/PowerSVX/certs

# Soft heap limit from host/cgroup RAM.
# Skipped when POWERSVX_GOMEMLIMIT_FIXED=1 (keep compose/env GOMEMLIMIT as-is).
# Note: `docker exec printenv GOMEMLIMIT` shows compose Env only — check PID1:
#   tr '\0' '\n' < /proc/1/environ | grep GOMEMLIMIT
# When Docker mem_limit is set (calc-mem-env), soft = 90% of that cgroup.
# When unlimited, soft = POWERSVX_MEM_PERCENT (default 40) of host × 90%.
apply_gomemlimit_percent() {
  if [ "${POWERSVX_GOMEMLIMIT_FIXED:-0}" = "1" ]; then
    if [ -n "${GOMEMLIMIT:-}" ]; then
      echo "gomem: fixed GOMEMLIMIT=$GOMEMLIMIT" >&2
    fi
    return 0
  fi
  percent=${POWERSVX_MEM_PERCENT:-40}
  case $percent in
    ''|*[!0-9]*) percent=40 ;;
  esac
  if [ "$percent" -lt 1 ] || [ "$percent" -gt 95 ]; then
    percent=40
  fi

  host_bytes=$(awk '/MemTotal:/ {printf "%.0f", $2*1024}' /proc/meminfo 2>/dev/null || echo 0)
  cgroup_bytes=""
  if [ -f /sys/fs/cgroup/memory.max ]; then
    v=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || true)
    if [ -n "$v" ] && [ "$v" != "max" ]; then
      cgroup_bytes=$v
    fi
  elif [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
    v=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || true)
    # Ignore absurd legacy "unlimited" sentinel.
    if [ -n "$v" ] && [ "$v" -lt 9223372036854771712 ]; then
      cgroup_bytes=$v
    fi
  fi

  # Soft = 90% of Docker mem_limit when set (calc-mem-env already applied MEM_PERCENT).
  # When unlimited (host network often used mem_limit=0), soft = MEM_PERCENT of host × 90%.
  if [ -n "$cgroup_bytes" ] && [ "$cgroup_bytes" -gt 0 ]; then
    base=$cgroup_bytes
    soft=$(( base * 90 / 100 ))
    export GOMEMLIMIT="${soft}B"
    echo "gomem: GOMEMLIMIT=$GOMEMLIMIT (90% of cgroup/mem_limit $base bytes)" >&2
    return 0
  fi

  base=$host_bytes
  if [ -z "$base" ] || [ "$base" -lt 268435456 ]; then
    echo "gomem: skip percent calc (base=${base:-0})" >&2
    return 0
  fi

  limit=$(( base * percent / 100 ))
  soft=$(( limit * 90 / 100 ))
  export GOMEMLIMIT="${soft}B"
  echo "gomem: GOMEMLIMIT=$GOMEMLIMIT (${percent}% of host $base bytes, 90% soft)" >&2
}

apply_gomemlimit_percent || true

# Prefer steadier GC under multi-GB heaps unless the operator set GOGC explicitly.
if [ -z "${GOGC:-}" ]; then
  export GOGC=50
fi

ensure_geodb() {
  # GEODB_AUTO_DOWNLOAD=0 skips. Path defaults to persistent volume file.
  if [ "${GEODB_AUTO_DOWNLOAD:-1}" = "0" ]; then
    return 0
  fi
  dest="${GEODB_PATH:-/data/dbip-country-lite.mmdb}"
  need=0
  if [ ! -s "$dest" ]; then
    need=1
  elif [ -n "$(find "$dest" -mtime +35 2>/dev/null)" ]; then
    need=1
  fi
  [ "$need" = "1" ] || return 0

  ym=$(date -u +%Y-%m)
  # Previous month (UTC): portable enough for GNU date in Debian.
  ym_prev=$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m 2>/dev/null || true)
  if [ -z "$ym_prev" ]; then
    ym_prev=$ym
  fi

  tmp="${dest}.tmp.gz"
  out="${dest}.tmp"
  ok=0
  for stamp in "$ym" "$ym_prev"; do
    url="https://download.db-ip.com/free/dbip-country-lite-${stamp}.mmdb.gz"
    echo "geodb: fetching $url" >&2
    if wget -q --timeout=60 -O "$tmp" "$url" \
      && gzip -dc "$tmp" > "$out" \
      && [ -s "$out" ]; then
      mv -f "$out" "$dest"
      ok=1
      echo "geodb: installed $dest (dbip-country-lite ${stamp}, CC BY 4.0 — https://db-ip.com)" >&2
      break
    fi
    rm -f "$tmp" "$out"
  done
  rm -f "$tmp" "$out"
  if [ "$ok" != "1" ]; then
    echo "geodb: download failed; GeoDNS will use overrides/default until MMDB is present" >&2
  fi
}

ensure_geodb || true

exec "$@"
