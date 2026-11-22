#!/usr/bin/env bash
# Turn dnsperf output (run with -O latency-histogram) into key=value lines.
#
# Usage: parse-dnsperf.sh [file]   (reads stdin without a file)
#
# Loss is computed from sent and completed. A percentile is the upper edge of
# the histogram bucket in which it falls; the keys are left empty when the
# output has no histogram.

set -euo pipefail

awk '
/Queries sent:/        { sent = $3 }
/Queries completed:/   { completed = $3 }
/Queries lost:/        { lost = $3 }
/Run time \(s\):/      { runtime = $4 }
/Queries per second:/  { qps = $4 }
/Average Latency \(s\):/ { avg = $4 }
/Latency bucket \(s\):/ { hist = 1; next }
hist && $2 == "-" && $3 ~ /:$/ {
  edge = $3; sub(/:$/, "", edge)
  hi[++nb] = edge; cnt[nb] = $4; answers += $4
}

function pct(p,    need, i, seen) {
  if (answers == 0) return ""
  need = answers * p / 100
  for (i = 1; i <= nb; i++) { seen += cnt[i]; if (seen >= need) return sprintf("%.3f", hi[i] * 1000) }
  return sprintf("%.3f", hi[nb] * 1000)
}

END {
  if (sent == "") { print "parse-dnsperf: no statistics found in the input" > "/dev/stderr"; exit 1 }
  printf "sent=%d\n", sent
  printf "completed=%d\n", completed
  printf "lost=%d\n", lost
  printf "loss_pct=%.4f\n", (sent > 0 ? 100 * (sent - completed) / sent : 100)
  printf "runtime_s=%.3f\n", runtime
  printf "qps=%.1f\n", qps
  printf "latency_avg_ms=%s\n", (avg == "" ? "" : sprintf("%.3f", avg * 1000))
  printf "latency_p50_ms=%s\n", pct(50)
  printf "latency_p95_ms=%s\n", pct(95)
  printf "latency_p99_ms=%s\n", pct(99)
}' "${1:-/dev/stdin}"
