#!/usr/bin/env bash
# Snapshot PowerSVX metrics for Unbound A/B comparison.
# Usage: ./scripts/ab-vs-unbound.sh [metrics_url]
set -euo pipefail
URL="${1:-http://127.0.0.1:9100/metrics}"
TMP="$(mktemp)"
curl -sS -m 5 "$URL" >"$TMP"

echo "=== PowerSVX A/B snapshot $(date -Is) ==="
echo "metrics: $URL"
echo

pick() { grep -E "^$1 " "$TMP" | awk '{print $2}' | head -1; }
pick_lab() { grep -E "^$1\\{" "$TMP" | head -20; }

echo "goroutines:        $(pick powersvx_goroutines)"
echo "resolve_inflight:  $(pick powersvx_resolve_inflight)"
echo "rss_bytes:         $(pick powersvx_process_rss_bytes)"
echo "cache_hits:        $(pick powersvx_cache_hits_total)"
echo "cache_stale_hits:  $(pick powersvx_cache_stale_hits_total)"
echo "cache_misses:      $(pick powersvx_cache_misses_total)"
echo "admit_rejected:    $(pick powersvx_admit_rejected_total)"
echo "rate_limited:      $(pick powersvx_rate_limited_total)"
echo
echo "--- path counts ---"
pick_lab powersvx_query_duration_by_path_seconds_count || true
echo
echo "--- queries by status ---"
pick_lab powersvx_queries_total || true
echo
echo "Compare to Unbound live stats: queries/s, cachehits, recursive, reqlist avg/max, loadavg."
echo "Gates: docs/UNBOUND-AB.md"
rm -f "$TMP"
