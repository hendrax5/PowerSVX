#!/bin/sh
# Choose the PowerSVX profile for this node: "full" or "core".
#
#   full  Core Profile + Observability Profile (Prometheus, Grafana, node-exporter)
#   core  Core Profile only (dnsdist, Unbound, Control Plane, Watchtower)
#
# Prints the profile on stdout and the reason on stderr.
#
# Order of precedence:
#   1. POWERSVX_PROFILE in the environment, else in <repo>/.env (never sourced)
#   2. unless -e is given: host memory below 4096 MB selects core, else full
#
# -x  exit 0 if POWERSVX_PROFILE is set (environment or .env), 1 if it is not.
#     Bootstrap uses this to remove Observability containers only after an
#     explicit choice of core, never after an automatic one.
# -e  explicit only: an unset POWERSVX_PROFILE means full and memory is not
#     consulted. apply-update.sh uses this so existing nodes never change by default.
#
# Host memory comes from POWERSVX_HOST_MEM_MB when set, else /proc/meminfo.
set -e

LIMIT_MB=4096
explicit_only=0
if [ "${1:-}" = "-e" ]; then
  explicit_only=1
fi

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
profile=${POWERSVX_PROFILE:-}
source=environment
if [ -z "$profile" ] && [ -f "$ROOT/.env" ]; then
  profile=$(grep -E '^POWERSVX_PROFILE=' "$ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d "\"'\r" || true)
  source=.env
fi

if [ "${1:-}" = "-x" ]; then
  [ -n "$profile" ]
  exit
fi

case "$profile" in
  full|core)
    echo "$profile"
    echo "profile $profile (POWERSVX_PROFILE from $source)" >&2
    exit 0
    ;;
  '') ;;
  *)
    echo "POWERSVX_PROFILE must be 'full' or 'core' (got '$profile')" >&2
    exit 1
    ;;
esac

if [ "$explicit_only" = 1 ]; then
  echo full
  echo "profile full (POWERSVX_PROFILE not set)" >&2
  exit 0
fi

case "${POWERSVX_HOST_MEM_MB:-}" in
  '') mem_mb=$(awk '/MemTotal:/ {print int($2 / 1024)}' /proc/meminfo) ;;
  *[!0-9]*) echo "POWERSVX_HOST_MEM_MB must be a whole number of MB" >&2; exit 1 ;;
  *) mem_mb=$POWERSVX_HOST_MEM_MB ;;
esac
if [ -z "$mem_mb" ] || [ "$mem_mb" -lt 64 ]; then
  echo "cannot read MemTotal" >&2
  exit 1
fi

if [ "$mem_mb" -lt "$LIMIT_MB" ]; then
  echo core
  echo "profile core (host has ${mem_mb} MB, under ${LIMIT_MB} MB; set POWERSVX_PROFILE=full to override)" >&2
else
  echo full
  echo "profile full (host has ${mem_mb} MB)" >&2
fi
