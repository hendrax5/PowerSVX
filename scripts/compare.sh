#!/usr/bin/env bash
# Side-by-side load comparison: PowerSVX vs Unbound / PowerDNS / Technitium.
#
# For every scenario × target it runs the same load with cmd/dnsbench and
# samples the target process CPU + peak RSS from /proc (Linux), then prints a
# markdown table: sustainable QPS, p99, CPU per 10k queries, peak memory.
#
# Usage:
#   scripts/compare.sh
#
#   TARGETS="powersvx|127.0.0.1:53|powersvx \
#            unbound|127.0.0.1:5353|unbound" \
#   DOMAIN=example.com. DURATION=20s CONC=200 scripts/compare.sh
set -euo pipefail

cd "$(dirname "$0")/.."

BENCH=bin/dnsbench
if [[ ! -x "$BENCH" ]]; then
  echo "[compare] building dnsbench..."
  mkdir -p bin
  go build -o "$BENCH" ./cmd/dnsbench
fi

DOMAIN="${DOMAIN:-example.com.}"
DURATION="${DURATION:-20s}"
CONC="${CONC:-200}"
SCENARIOS="${SCENARIOS:-hit mixed nx}"

# Default: live PowerSVX on :53 (host-network Docker / systemd).
TARGETS="${TARGETS:-powersvx|127.0.0.1:53|powersvx}"

CLK=$(getconf CLK_TCK)
NCPU=$(nproc)

pid_for() {
  [[ "$1" == "-" ]] && return 0
  pgrep -f "$1" | head -n1 || true
}

cpu_ticks() {
  local pid="$1"
  [[ -z "$pid" || ! -r "/proc/$pid/stat" ]] && { echo 0; return; }
  awk '{print $14+$15}' "/proc/$pid/stat" 2>/dev/null || echo 0
}

rss_kb() {
  local pid="$1"
  [[ -z "$pid" || ! -r "/proc/$pid/status" ]] && { echo 0; return; }
  awk '/VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0
}

RESULTS=()

run_one() {
  local name="$1" host="$2" scenario="$3" pattern="$4"
  local pid; pid="$(pid_for "$pattern")"

  local c0; c0="$(cpu_ticks "$pid")"
  local peak=0
  ( while true; do
      r="$(rss_kb "$pid")"; [[ "$r" -gt "$peak" ]] && peak="$r"
      echo "$peak" > "/tmp/.cmp_rss_$$"; sleep 0.2
    done ) &
  local sampler=$!

  local out; out="$("$BENCH" -server "$host" -mode "$scenario" -domain "$DOMAIN" -c "$CONC" -d "$DURATION")"
  kill "$sampler" 2>/dev/null || true
  wait "$sampler" 2>/dev/null || true
  peak="$(cat "/tmp/.cmp_rss_$$" 2>/dev/null || echo 0)"; rm -f "/tmp/.cmp_rss_$$"

  local c1; c1="$(cpu_ticks "$pid")"

  local sent qps p99
  sent="$(sed -n 's/.*sent=\([0-9]*\).*/\1/p' <<<"$out" | head -n1)"
  qps="$(sed -n 's/QPS(sustained) = \([0-9.]*\).*/\1/p' <<<"$out" | head -n1)"
  p99="$(sed -n 's/.*p99=\([^ ]*\).*/\1/p' <<<"$out" | head -n1)"

  local cpu_per_10k="n/a" mem="n/a"
  if [[ -n "$pid" && "$pattern" != "-" ]]; then
    local dcpu; dcpu="$(echo "scale=3; ($c1-$c0)/$CLK" | bc)"
    if [[ -n "${sent:-}" && "$sent" -gt 0 ]]; then
      cpu_per_10k="$(echo "scale=4; $dcpu/($sent/10000)" | bc) cpu-s"
    fi
    mem="$(echo "scale=1; $peak/1024" | bc) MiB"
  fi

  RESULTS+=("$scenario|$name|${qps:-n/a}|${p99:-n/a}|$cpu_per_10k|$mem")
  printf '  %-10s %-12s QPS=%-8s p99=%-10s CPU/10k=%-14s peakRSS=%s\n' \
    "$scenario" "$name" "${qps:-n/a}" "${p99:-n/a}" "$cpu_per_10k" "$mem"
}

echo "=========================================================="
echo " PowerSVX comparison"
echo " domain=$DOMAIN duration=$DURATION concurrency=$CONC cpus=$NCPU"
echo "=========================================================="

for scenario in $SCENARIOS; do
  echo "-- scenario: $scenario --"
  for entry in $TARGETS; do
    IFS='|' read -r name host pattern <<<"$entry"
    run_one "$name" "$host" "$scenario" "${pattern:--}"
  done
done

echo
echo "## Results (side by side)"
echo
echo "| Scenario | Resolver | QPS (sustained) | p99 latency | CPU per 10k queries | Peak memory |"
echo "|----------|----------|-----------------|-------------|---------------------|-------------|"
for row in "${RESULTS[@]}"; do
  IFS='|' read -r sc nm qps p99 cpu mem <<<"$row"
  printf '| %s | %s | %s | %s | %s | %s |\n' "$sc" "$nm" "$qps" "$p99" "$cpu" "$mem"
done
echo
echo "Notes: CPU/mem sampled from /proc for the matched PID. Lower CPU-per-10k and"
echo "lower peak memory at equal/higher QPS and stable p99 = the winner."
