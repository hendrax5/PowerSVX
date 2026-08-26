#!/bin/sh
# Compute Docker mem_limit + GOMEMLIMIT as a percentage of host RAM.
# Usage (on the server, before compose up):
#   . deploy/linux/calc-mem-env.sh   # exports into current shell
#   # or:
#   deploy/linux/calc-mem-env.sh > .env.mem && set -a && . ./.env.mem && set +a
#
# Env:
#   POWERSVX_MEM_PERCENT   default 40  (hard Docker cgroup limit; ~4GiB soft on 11GB)
#   POWERSVX_GOMEM_RATIO   default 90  (% of that limit for GOMEMLIMIT)
set -e
PERCENT=${POWERSVX_MEM_PERCENT:-40}
GORATIO=${POWERSVX_GOMEM_RATIO:-90}
case $PERCENT in
  ''|*[!0-9]*) echo "POWERSVX_MEM_PERCENT must be integer 1-95" >&2; exit 1 ;;
esac
if [ "$PERCENT" -lt 1 ] || [ "$PERCENT" -gt 95 ]; then
  echo "POWERSVX_MEM_PERCENT must be 1-95 (got $PERCENT)" >&2
  exit 1
fi

MEM_KB=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
if [ -z "$MEM_KB" ] || [ "$MEM_KB" -lt 65536 ]; then
  echo "cannot read MemTotal" >&2
  exit 1
fi

# Docker mem_limit wants a byte integer or unit suffix; plain bytes is fine.
LIMIT_BYTES=$(( MEM_KB * 1024 * PERCENT / 100 ))
GOMEM_BYTES=$(( LIMIT_BYTES * GORATIO / 100 ))

# Export when sourced; always print KEY=value for .env files.
POWERSVX_MEM_LIMIT=$LIMIT_BYTES
GOMEMLIMIT=${GOMEM_BYTES}B
export POWERSVX_MEM_LIMIT GOMEMLIMIT

echo "POWERSVX_MEM_LIMIT=$POWERSVX_MEM_LIMIT"
echo "GOMEMLIMIT=$GOMEMLIMIT"
echo "# host MemTotal=${MEM_KB}kB percent=${PERCENT}% gomem_ratio=${GORATIO}%" >&2
