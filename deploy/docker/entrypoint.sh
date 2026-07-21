#!/bin/sh
# Ensure data dirs exist; optionally fetch free DB-IP Country Lite (CC BY 4.0).
# Run as root so privileged ports (53/853/443) bind reliably.
set -e
mkdir -p /data/cache /var/log/PowerSVX /etc/PowerSVX/certs

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
