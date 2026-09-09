#!/bin/sh
# Guard before Unbound recreate / RPZ reload on small hosts.
# Usage (on server):
#   bash deploy/linux/unbound-rpz-guard.sh
#   bash deploy/linux/unbound-rpz-guard.sh --park   # move huge zone aside if unsafe
#
# Env:
#   POWERSVX_RPZ_MIN_AVAIL_MB  default 3500  (MemAvailable required to keep full TrustPositif)
#   POWERSVX_RPZ_HUGE_BYTES     default 120000000 (~120MB; full ~9.5M zone is larger)
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
RPZ_DIR="${POWERSVX_UNBOUND_RPZ_DIR:-$ROOT/data/unbound-rpz}"
ZONE="$RPZ_DIR/trustpositif.rpz"
PARKED="$RPZ_DIR/trustpositif.rpz.parked"
MIN_AVAIL_MB="${POWERSVX_RPZ_MIN_AVAIL_MB:-3500}"
HUGE_BYTES="${POWERSVX_RPZ_HUGE_BYTES:-120000000}"
# ~120MB ≈ multi-million names. Partial TrustPositif (~1.5M) stays under this;
# full ~9.5M zone (~370MB) is still treated as unsafe on small hosts.
DO_PARK=0
case "${1:-}" in
  --park) DO_PARK=1 ;;
esac

AVAIL_KB=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
TOTAL_KB=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
AVAIL_MB=$((AVAIL_KB / 1024))
TOTAL_MB=$((TOTAL_KB / 1024))

zone_bytes=0
if [ -f "$ZONE" ]; then
  zone_bytes=$(wc -c <"$ZONE" | tr -d ' ')
fi

echo "unbound-rpz-guard: MemTotal=${TOTAL_MB}MB MemAvailable=${AVAIL_MB}MB zone=${zone_bytes}B min_avail=${MIN_AVAIL_MB}MB" >&2

if [ "$zone_bytes" -lt "$HUGE_BYTES" ]; then
  echo "unbound-rpz-guard: zone small/empty — OK to start Unbound" >&2
  exit 0
fi

if [ "$AVAIL_MB" -ge "$MIN_AVAIL_MB" ] && [ "$TOTAL_MB" -ge 14000 ]; then
  echo "unbound-rpz-guard: host has headroom for full TrustPositif — OK" >&2
  exit 0
fi

echo "unbound-rpz-guard: UNSAFE to load full TrustPositif on this host (need ≥~${MIN_AVAIL_MB}MB available and prefer ≥16GB RAM)" >&2

if [ "$DO_PARK" = 1 ]; then
  mkdir -p "$RPZ_DIR"
  if [ -f "$ZONE" ]; then
    mv -f "$ZONE" "$PARKED"
    echo "unbound-rpz-guard: parked -> $PARKED" >&2
  fi
  cat >"$ZONE" <<'EOF'
$TTL 60
$ORIGIN rpz.trustpositif.
@ SOA localhost. root.localhost. 1 3600 600 86400 60
@ NS localhost.
EOF
  echo "unbound-rpz-guard: wrote empty trustpositif.rpz so DNS can boot" >&2
  exit 0
fi

echo "unbound-rpz-guard: refusing — re-run with --park to boot DNS without full RPZ, or upgrade RAM" >&2
exit 2
