#!/usr/bin/env bash
# Limit the system under test to a smaller node: a fixed set of CPUs and a memory cap,
# shared by everything placed in the slice, so a stack of several containers is held to
# the same total as a single container.
#
# Usage (as root):
#   size-slice.sh up [-c CPUS] [-m MB]   create and start powersvx-bench.slice (default 2 CPUs, 2048 MB)
#   size-slice.sh env [-c CPUS] [-m MB]  print the sizing variables for the config generators
#   size-slice.sh status                 show the limits the kernel enforces
#   size-slice.sh down                   remove the slice (refuses while anything runs in it)
#
# Containers join the slice with `--cgroup-parent powersvx-bench.slice`
# (technitium.sh does this; deploy/linux/docker-compose.bench-small.yml does it for PowerSVX).
#
# CPUs are pinned with a cpuset (the first N CPUs) rather than a CPU quota, so the
# processes see N CPUs, as on a real N-vCPU node, and are not throttled in bursts.
# Needs cgroup v2 and systemd 244 or newer. The unit lives in /run, so a reboot removes it.

set -euo pipefail

SLICE=powersvx-bench.slice
UNIT=/run/systemd/system/$SLICE

# systemd reads a dash in a slice name as nesting: powersvx-bench.slice lives inside
# powersvx.slice, so the cgroup path is /sys/fs/cgroup/powersvx.slice/powersvx-bench.slice.
slice_path() {
  local acc="" out="" part
  local -a parts
  IFS=- read -ra parts <<<"${1%.slice}"
  for part in "${parts[@]}"; do
    acc="${acc:+$acc-}$part"
    out+="/$acc.slice"
  done
  echo "/sys/fs/cgroup$out"
}
CGROUP="$(slice_path "$SLICE")"

# Processes in the slice and in every cgroup below it. A container sits in its own
# docker-<id>.scope under the slice, so the slice's own cgroup.procs is always empty.
members() {
  [ -d "$CGROUP" ] || { echo 0; return; }
  find "$CGROUP" -name cgroup.procs -exec cat {} + 2>/dev/null | wc -l | tr -d ' '
}

die() { echo "size-slice: $*" >&2; exit 2; }

cmd="${1:-}"
[ -n "$cmd" ] || die "usage: size-slice.sh up|env|status|down (see the header of this script)"
shift

cpus=2
mem_mb=2048
while getopts "c:m:" opt; do
  case "$opt" in
    c) cpus="$OPTARG" ;;
    m) mem_mb="$OPTARG" ;;
    *) die "unknown option" ;;
  esac
done
[[ "$cpus" =~ ^[1-9][0-9]*$ ]] || die "-c must be a positive whole number"
[[ "$mem_mb" =~ ^[1-9][0-9]*$ ]] || die "-m must be a whole number of MB"

case "$cmd" in
  env)
    echo "export POWERSVX_HOST_CPUS=$cpus"
    echo "export POWERSVX_HOST_MEM_MB=$mem_mb"
    ;;

  up)
    [ "$(id -u)" -eq 0 ] || die "run as root"
    [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = "cgroup2fs" ] || die "cgroup v2 is required"
    command -v systemctl >/dev/null 2>&1 || die "systemd is required"
    ver="$(systemctl --version | awk 'NR==1 {print $2}')"
    [ "${ver:-0}" -ge 244 ] || die "systemd 244 or newer is required (found ${ver:-unknown})"
    total="$(nproc --all)"
    [ "$cpus" -le "$total" ] || die "this machine has only $total CPUs"
    if [ "$(members)" -gt 0 ]; then
      die "$SLICE already has running processes; stop them first"
    fi
    last=$((cpus - 1))
    mkdir -p "$(dirname "$UNIT")"
    cat >"$UNIT" <<EOF
[Unit]
Description=PowerSVX benchmark size limit (${cpus} CPUs, ${mem_mb} MB)

[Slice]
AllowedCPUs=0-${last}
MemoryMax=${mem_mb}M
MemorySwapMax=0
CPUAccounting=yes
MemoryAccounting=yes
EOF
    systemctl daemon-reload
    systemctl start "$SLICE"
    echo "size-slice: $SLICE up: CPUs 0-$last, ${mem_mb} MB, no swap" >&2
    ;;

  status)
    # systemd creates the slice's cgroup only when something joins it, so ask systemd first.
    [ "$(systemctl is-active "$SLICE" 2>/dev/null || true)" = active ] ||
      { echo "size-slice: $SLICE is not running" >&2; exit 1; }
    systemctl show "$SLICE" -p AllowedCPUs -p MemoryMax -p MemorySwapMax
    if [ -d "$CGROUP" ]; then
      echo "members: $(members) processes, $(($(cat "$CGROUP/memory.current") / 1048576)) MiB in use"
    else
      echo "members: none yet"
    fi
    ;;

  down)
    [ "$(id -u)" -eq 0 ] || die "run as root"
    if [ "$(members)" -gt 0 ]; then
      die "$SLICE still has running processes; stop the containers in it first"
    fi
    systemctl stop "$SLICE" 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload
    echo "size-slice: $SLICE removed" >&2
    ;;

  *) die "unknown command '$cmd'" ;;
esac
