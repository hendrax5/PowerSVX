#!/usr/bin/env bash
# Measure a DNS server under the Reference Load and write one results file.
#
# Run this on the load-generating machine, never on the server under test.
#
# Usage:
#   run.sh -s SERVER -d QUERIES -l LABEL [options]
#
#   -s HOST   server under test
#   -d FILE   query set in dnsperf format (see gen-queryset.sh)
#   -l LABEL  name for this run, used in the results file name
#   -p PORT   UDP port (default 53)
#   -o DIR    results directory (default ./results)
#   -S DEST   ssh destination of the server, to record hardware, images and
#             per-service memory (optional; without it those fields stay empty)
#   -c N      dnsperf clients (default 100)
#   -T N      dnsperf threads (default: CPUs on this machine)
#   -q N      dnsperf maximum outstanding queries (default 10000)
#   -W QPS    warm-up rate (default 2000)
#   -t SEC    length of each search step (default 30)
#   -m SEC    length of the final measurement (default 120)
#   -L PCT    highest loss that still counts as keeping up (default 0.1)
#   -n NOTE   free-text note stored in the results file
#
# What it does:
#   1. waits until the server answers DNS;
#   2. warms the server by sending every distinct query once;
#   3. finds the highest rate at which loss stays at or below the limit:
#      an unthrottled run first, then a binary search below it;
#   4. measures at that rate, recording latency percentiles;
#   5. samples per-service memory on the server halfway through step 4.
#
# Environment:
#   DNSPERF       dnsperf binary (default: dnsperf)
#   BENCH_REMOTE  command used instead of "ssh DEST" to reach the server; it gets
#                 one argument, the command line to run there
#   BENCH_PAUSE   seconds to let queues drain between runs (default 2)

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
DNSPERF="${DNSPERF:-dnsperf}"
READY="${BENCH_READY:-$here/../../deploy/linux/dns-ready.sh}"
[ -f "$READY" ] || READY="$here/dns-ready.sh"

server="" queries="" label="" port=53 outdir="./results" ssh_dest=""
clients=100 threads="$(nproc 2>/dev/null || echo 2)" outstanding=10000
warm_qps=2000 step_s=30 measure_s=120 max_loss=0.1 note=""
pause="${BENCH_PAUSE:-2}"

die() { echo "bench: $*" >&2; exit 2; }
log() { echo "bench: $*" >&2; }

while getopts "s:d:l:p:o:S:c:T:q:W:t:m:L:n:" opt; do
  case "$opt" in
    s) server="$OPTARG" ;;
    d) queries="$OPTARG" ;;
    l) label="$OPTARG" ;;
    p) port="$OPTARG" ;;
    o) outdir="$OPTARG" ;;
    S) ssh_dest="$OPTARG" ;;
    c) clients="$OPTARG" ;;
    T) threads="$OPTARG" ;;
    q) outstanding="$OPTARG" ;;
    W) warm_qps="$OPTARG" ;;
    t) step_s="$OPTARG" ;;
    m) measure_s="$OPTARG" ;;
    L) max_loss="$OPTARG" ;;
    n) note="$OPTARG" ;;
    *) die "unknown option (see the header of this script)" ;;
  esac
done

[ -n "$server" ] || die "-s server is required"
[ -s "$queries" ] || die "-d query set '$queries' is missing or empty"
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || die "-l label must use only letters, digits, dot, dash and underscore"
command -v "$DNSPERF" >/dev/null 2>&1 || die "dnsperf not found (set DNSPERF or use the load generator image)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$outdir"

remote() {
  if [ -n "${BENCH_REMOTE:-}" ]; then
    $BENCH_REMOTE "$@"
  elif [ -n "$ssh_dest" ]; then
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$ssh_dest" "$@"
  else
    return 1
  fi
}

# Runs dnsperf once and loads its parsed statistics into the array R.
# $1 rate (0 = unthrottled)  $2 seconds  $3 output file  $4 extra dnsperf args
declare -A R
measure() {
  local rate="$1" seconds="$2" out="$3"
  local args=(-s "$server" -p "$port" -d "$queries" -l "$seconds" -c "$clients" -T "$threads"
              -q "$outstanding" -t 2 -O latency-histogram)
  [ "$rate" -gt 0 ] && args+=(-Q "$rate")
  "$DNSPERF" "${args[@]}" >"$out" 2>&1 || true
  R=()
  local k v
  while IFS='=' read -r k v; do R[$k]="$v"; done < <(bash "$here/parse-dnsperf.sh" "$out")
  [ -n "${R[sent]:-}" ] || { cat "$out" >&2; die "dnsperf produced no statistics"; }
}

kept_up() {
  awk -v loss="${R[loss_pct]}" -v limit="$max_loss" -v done="${R[completed]}" \
    'BEGIN { exit !(done > 0 && loss <= limit) }'
}

steps=""
record_step() { # $1 requested rate
  steps+="${steps:+,}{\"requested_qps\":$1,\"achieved_qps\":${R[qps]},\"loss_pct\":${R[loss_pct]}}"
  log "  rate=$1 achieved=${R[qps]} qps loss=${R[loss_pct]}%"
}

log "1/5 waiting for $server:$port to answer"
bash "$READY" -s "$server" -p "$port" -w 60 -u invalid || die "$server:$port does not answer DNS"

log "2/5 warm-up at $warm_qps qps"
sort -u "$queries" >"$work/distinct.txt"
"$DNSPERF" -s "$server" -p "$port" -d "$work/distinct.txt" -n 1 -Q "$warm_qps" -c "$clients" -T "$threads" -t 5 \
  >"$work/warm.txt" 2>&1 || true

log "3/5 searching for the highest rate with loss <= ${max_loss}%"
measure 0 "$step_s" "$work/step-0.txt"
record_step 0
limited_by="server"
if kept_up; then
  # The server kept up with everything this machine could send.
  best=0
  limited_by="load generator"
else
  lo=0
  hi="$(awk -v s="${R[sent]}" -v t="${R[runtime_s]}" 'BEGIN { printf "%d", s / t }')"
  for i in 1 2 3 4 5 6 7; do
    mid=$(((lo + hi) / 2))
    [ "$mid" -gt 0 ] || break
    sleep "$pause"
    measure "$mid" "$step_s" "$work/step-$i.txt"
    record_step "$mid"
    if kept_up; then lo="$mid"; else hi="$mid"; fi
  done
  best="$lo"
  [ "$best" -gt 0 ] || die "no rate was found at which loss stays at or below ${max_loss}%"
fi

log "4/5 measuring for ${measure_s}s at $([ "$best" -gt 0 ] && echo "$best qps" || echo "full speed")"
mem_file="$work/mem.txt"
: >"$mem_file"
(
  sleep $((measure_s / 2))
  remote "docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}'" >"$mem_file" 2>/dev/null || true
) &
sampler=$!
sleep "$pause"
measure "$best" "$measure_s" "$work/final.txt"
wait "$sampler" || true
passed=false
kept_up && passed=true

log "5/5 collecting server details"
target_cpus="$(remote nproc 2>/dev/null || true)"
target_mem_kb="$(remote 'grep -m1 MemTotal: /proc/meminfo' 2>/dev/null | tr -dc '0-9' || true)"
target_kernel="$(remote 'uname -r' 2>/dev/null || true)"
remote "docker ps --format '{{.Names}} {{.Image}}'" >"$work/images.txt" 2>/dev/null || true

json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/  /g' | tr -d '\r\n'; }
json_lines() { # file -> JSON array of strings
  local first=1 line
  printf '['
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    [ "$first" = 1 ] || printf ','
    first=0
    printf '"%s"' "$(json_str "$line")"
  done <"$1"
  printf ']'
}
num() { [ -n "${1:-}" ] && printf '%s' "$1" || printf 'null'; }

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$outdir/${label}-${stamp}.json"
cat >"$out" <<EOF
{
  "label": "$(json_str "$label")",
  "taken_at_utc": "$stamp",
  "note": "$(json_str "$note")",
  "passed": $passed,
  "max_loss_pct": $max_loss,
  "max_qps": ${R[qps]},
  "limited_by": "$limited_by",
  "loss_pct": ${R[loss_pct]},
  "sent": ${R[sent]},
  "completed": ${R[completed]},
  "latency_ms": {
    "avg": $(num "${R[latency_avg_ms]}"),
    "p50": $(num "${R[latency_p50_ms]}"),
    "p95": $(num "${R[latency_p95_ms]}"),
    "p99": $(num "${R[latency_p99_ms]}")
  },
  "search_steps": [$steps],
  "server": {
    "address": "$(json_str "$server")",
    "port": $port,
    "cpus": $(num "$target_cpus"),
    "mem_total_kb": $(num "$target_mem_kb"),
    "kernel": "$(json_str "$target_kernel")",
    "images": $(json_lines "$work/images.txt"),
    "memory_under_load": $(json_lines "$mem_file")
  },
  "load_generator": {
    "dnsperf": "$(json_str "$("$DNSPERF" -h 2>&1 | grep -m1 -i '^Version' || true)")",
    "clients": $clients,
    "threads": $threads,
    "max_outstanding": $outstanding,
    "warm_up_qps": $warm_qps,
    "step_seconds": $step_s,
    "measure_seconds": $measure_s
  },
  "query_set": {
    "file": "$(json_str "$(basename "$queries")")",
    "lines": $(wc -l <"$queries" | tr -d ' '),
    "distinct": $(wc -l <"$work/distinct.txt" | tr -d ' '),
    "sha256": "$(sha256sum "$queries" | cut -d' ' -f1)"
  }
}
EOF

log "wrote $out"
log "max_qps=${R[qps]} loss=${R[loss_pct]}% p99=${R[latency_p99_ms]:-n/a}ms limited_by=$limited_by passed=$passed"
echo "$out"
