#!/usr/bin/env bash
# Compare two results files side by side and say whether the comparison is fair.
#
# Usage: compare.sh A.json B.json
#
# Exit status: 0 when the runs are comparable, 1 when they are not (different query set,
# load generator settings, size or server hardware), 2 on bad input. The table is printed
# either way, with the reasons after it.
#
# Needs jq.

set -euo pipefail

die() { echo "compare: $*" >&2; exit 2; }

[ $# -eq 2 ] || die "usage: compare.sh A.json B.json"
command -v jq >/dev/null 2>&1 || die "jq is required"
for f in "$1" "$2"; do
  [ -s "$f" ] || die "'$f' is missing or empty"
  jq -e 'has("max_qps") and has("latency_ms") and has("query_set")' "$f" >/dev/null 2>&1 ||
    die "'$f' is not a results file written by run.sh"
done

# Memory in MiB from the "name used / limit cpu%" lines docker stats gave.
MEM='[.server.memory_under_load[]?
      | capture("^(?<n>\\S+) (?<v>[0-9.]+)(?<u>[A-Za-z]+) / ")
      | (.v | tonumber) * (if .u == "B" then 1/1048576
                            elif .u == "KiB" or .u == "kB" then 1/1024
                            elif .u == "MiB" or .u == "MB" then 1
                            elif .u == "GiB" or .u == "GB" then 1024
                            else 0 end)]'

get() { jq -r "$2" "$1"; }

row() { printf '%-26s %-28s %-28s\n' "$1" "$2" "$3"; }

mem_text() { if [ -n "$1" ]; then echo "$1 MiB"; else echo "not recorded"; fi; }

fmt_ms() { awk -v v="$1" 'BEGIN { if (v == "" || v == "null") print "n/a"; else printf "%.3f ms", v }'; }

A="$1"
B="$2"
mem_a="$(get "$A" "$MEM | if length == 0 then \"\" else add | . * 10 | round / 10 end")"
mem_b="$(get "$B" "$MEM | if length == 0 then \"\" else add | . * 10 | round / 10 end")"

echo
row "" "A" "B"
row "file" "$(basename "$A")" "$(basename "$B")"
row "system" "$(get "$A" '.system // "unknown"')" "$(get "$B" '.system // "unknown"')"
row "size" "$(get "$A" '.size // "full"')" "$(get "$B" '.size // "full"')"
row "max qps" "$(get "$A" '.max_qps')" "$(get "$B" '.max_qps')"
row "loss" "$(get "$A" '.loss_pct')%" "$(get "$B" '.loss_pct')%"
row "latency p50" "$(fmt_ms "$(get "$A" '.latency_ms.p50')")" "$(fmt_ms "$(get "$B" '.latency_ms.p50')")"
row "latency p95" "$(fmt_ms "$(get "$A" '.latency_ms.p95')")" "$(fmt_ms "$(get "$B" '.latency_ms.p95')")"
row "latency p99" "$(fmt_ms "$(get "$A" '.latency_ms.p99')")" "$(fmt_ms "$(get "$B" '.latency_ms.p99')")"
row "limited by" "$(get "$A" '.limited_by')" "$(get "$B" '.limited_by')"
row "within limits" "$(get "$A" '.passed')" "$(get "$B" '.passed')"
row "memory under load" "$(mem_text "$mem_a")" "$(mem_text "$mem_b")"
row "server CPUs" "$(get "$A" '.server.cpus // "n/a"')" "$(get "$B" '.server.cpus // "n/a"')"
row "server memory" "$(get "$A" 'if .server.mem_total_kb then "\(.server.mem_total_kb / 1048576 | . * 10 | round / 10) GiB" else "n/a" end')" \
  "$(get "$B" 'if .server.mem_total_kb then "\(.server.mem_total_kb / 1048576 | . * 10 | round / 10) GiB" else "n/a" end')"

echo
qa="$(get "$A" '.max_qps')"
qb="$(get "$B" '.max_qps')"
awk -v a="$qa" -v b="$qb" 'BEGIN { if (b > 0) printf "max qps:  A is %.2fx B\n", a / b }'
if [ -n "$mem_a" ] && [ -n "$mem_b" ]; then
  awk -v a="$mem_a" -v b="$mem_b" 'BEGIN { if (b > 0) printf "memory:   A uses %.2fx the memory of B\n", a / b }'
fi

echo
problems=()
notes=()

[ "$(get "$A" '.query_set.sha256')" = "$(get "$B" '.query_set.sha256')" ] ||
  problems+=("the query sets differ (different SHA-256)")
[ "$(get "$A" '.load_generator | del(.dnsperf) | tojson')" = "$(get "$B" '.load_generator | del(.dnsperf) | tojson')" ] ||
  problems+=("the load generator settings differ (clients, threads, outstanding limit, warm-up or step lengths)")
[ "$(get "$A" '.load_generator.dnsperf')" = "$(get "$B" '.load_generator.dnsperf')" ] ||
  problems+=("the dnsperf versions differ")
[ "$(get "$A" '.size // "full"')" = "$(get "$B" '.size // "full"')" ] ||
  problems+=("the sizes differ (full against small)")
[ "$(get "$A" '.max_loss_pct')/$(get "$A" '.max_p99_ms // "none"')" = "$(get "$B" '.max_loss_pct')/$(get "$B" '.max_p99_ms // "none"')" ] ||
  problems+=("the loss or p99 limits differ")
ha="$(get "$A" '[.server.cpus, .server.mem_total_kb] | tojson')"
hb="$(get "$B" '[.server.cpus, .server.mem_total_kb] | tojson')"
if [ "$ha" != "[null,null]" ] && [ "$hb" != "[null,null]" ] && [ "$ha" != "$hb" ]; then
  problems+=("the server hardware differs")
fi
if [ "$ha" = "[null,null]" ] || [ "$hb" = "[null,null]" ]; then
  notes+=("server hardware was not recorded in at least one file, so it cannot be checked (run with -S)")
fi
for side in A B; do
  f="$A"
  [ "$side" = B ] && f="$B"
  [ "$(get "$f" '.limited_by')" != "load generator" ] ||
    notes+=("$side: the load generator was the limit, so its maximum is a floor, not the server's limit")
  [ "$(get "$f" '.passed')" = "true" ] ||
    notes+=("$side: the final measurement was outside the loss or latency limits")
done
[ -n "$mem_a" ] && [ -n "$mem_b" ] ||
  notes+=("memory was not recorded in at least one file (run with -S and -R)")

if [ ${#problems[@]} -eq 0 ]; then
  echo "COMPARABLE: yes"
else
  echo "COMPARABLE: no"
  for p in "${problems[@]}"; do echo "  - $p"; done
fi
for n in "${notes[@]+"${notes[@]}"}"; do echo "note: $n"; done

[ ${#problems[@]} -eq 0 ]
