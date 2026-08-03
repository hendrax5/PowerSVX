#!/bin/sh
# Ensure data dirs exist; optionally fetch free DB-IP Country Lite (CC BY 4.0).
# Run as root so privileged ports (53/853/443) bind reliably.
set -e
mkdir -p /data/cache /var/log/PowerSVX /etc/PowerSVX/certs

# Soft heap limit: POWERSVX_MEM_PERCENT of host (or cgroup) RAM. Default 70%.
# Skipped when POWERSVX_GOMEMLIMIT_FIXED=1 (keep compose/env GOMEMLIMIT as-is).
apply_gomemlimit_percent() {
  if [ "${POWERSVX_GOMEMLIMIT_FIXED:-0}" = "1" ]; then
    return 0
  fi
  percent=${POWERSVX_MEM_PERCENT:-70}
  case $percent in
    ''|*[!0-9]*) percent=70 ;;
  esac
  if [ "$percent" -lt 1 ] || [ "$percent" -gt 95 ]; then
    percent=70
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

  base=$host_bytes
  if [ -n "$cgroup_bytes" ] && [ "$cgroup_bytes" -gt 0 ]; then
    if [ -z "$base" ] || [ "$base" -le 0 ] || [ "$cgroup_bytes" -lt "$base" ]; then
      base=$cgroup_bytes
    fi
  fi
  if [ -z "$base" ] || [ "$base" -lt 268435456 ]; then
    echo "gomem: skip percent calc (base=${base:-0})" >&2
    return 0
  fi

  # Soft limit = percent of base; leave a little headroom under hard cgroup for native allocs.
  limit=$(( base * percent / 100 ))
  soft=$(( limit * 90 / 100 ))
  export GOMEMLIMIT="${soft}B"
  echo "gomem: GOMEMLIMIT=$GOMEMLIMIT (${percent}% of $base bytes, 90% soft)" >&2
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
