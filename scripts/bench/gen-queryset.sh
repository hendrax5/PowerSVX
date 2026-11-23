#!/usr/bin/env bash
# Generate a synthetic Reference Load query set in dnsperf format ("name TYPE").
#
# The mix is: popular names drawn with a Zipf distribution, names from the
# Filter, and names that do not exist. The same inputs and seed always give
# the same output, on any awk.
#
# Usage:
#   gen-queryset.sh -p popular.txt [-f filter.txt] [options] > queries.txt
#
#   -p FILE  popular names, most popular first; plain names or "rank,name" CSV
#   -f FILE  Filter names, one per line (required unless -F 0)
#   -n N     lines to write (default 1000000)
#   -k N     how many popular names to use (default 100000)
#   -K N     how many Filter names to use (default 50000)
#   -x N     size of the pool of non-existent names (default 20000)
#   -F PCT   share of queries for Filter names (default 5)
#   -X PCT   share of queries for non-existent names (default 5)
#   -z S     Zipf exponent for popular names (default 1.0)
#   -s SEED  positive integer seed (default 1)
#
# Query types are 60% A, 30% AAAA, 10% HTTPS.
#
# Non-existent names all sit under one made-up top-level name and come from a
# fixed pool, so a resolver learns once that the suffix does not exist and the
# benchmark does not turn into a flood of junk queries at the root servers.

set -euo pipefail

popular=""
filter=""
lines=1000000
pop_pool=100000
filter_pool=50000
nx_pool=20000
filter_pct=5
nx_pct=5
zipf=1.0
seed=1
nx_suffix="psvxbench-nx"

die() { echo "gen-queryset: $*" >&2; exit 2; }

while getopts "p:f:n:k:K:x:F:X:z:s:" opt; do
  case "$opt" in
    p) popular="$OPTARG" ;;
    f) filter="$OPTARG" ;;
    n) lines="$OPTARG" ;;
    k) pop_pool="$OPTARG" ;;
    K) filter_pool="$OPTARG" ;;
    x) nx_pool="$OPTARG" ;;
    F) filter_pct="$OPTARG" ;;
    X) nx_pct="$OPTARG" ;;
    z) zipf="$OPTARG" ;;
    s) seed="$OPTARG" ;;
    *) die "unknown option (see the header of this script)" ;;
  esac
done

[ -n "$popular" ] || die "-p popular names file is required"
[ -s "$popular" ] || die "popular names file '$popular' is missing or empty"
[[ "$seed" =~ ^[1-9][0-9]*$ ]] || die "seed must be a positive integer"
if [ "$filter_pct" != "0" ]; then
  [ -n "$filter" ] || die "-f Filter names file is required unless -F 0"
  [ -s "$filter" ] || die "Filter names file '$filter' is missing or empty"
fi
[ -n "$filter" ] || filter=/dev/null

awk -v lines="$lines" -v pop_pool="$pop_pool" -v filter_pool="$filter_pool" \
    -v nx_pool="$nx_pool" -v filter_pct="$filter_pct" -v nx_pct="$nx_pct" \
    -v zipf="$zipf" -v seed="$seed" -v nx_suffix="$nx_suffix" '
# Park-Miller generator: every product stays below 2^53, so the sequence is
# identical on gawk, mawk and busybox awk.
function rnd() { state = (state * 16807) % 2147483647; return state / 2147483647 }

function clean(s) {
  sub(/\r$/, "", s); gsub(/^[ \t]+|[ \t]+$/, "", s)
  sub(/^\*\./, "", s); sub(/\.$/, "", s)
  return tolower(s)
}
function valid(s) { return s ~ /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/ }

FNR == 1 { file++ }
/^[ \t]*(#|$)/ { next }
file == 1 {
  n = split($0, parts, ",")
  name = clean(parts[n])
  if (npop < pop_pool && valid(name)) pop[++npop] = name
  next
}
file == 2 {
  name = clean($1)
  if (nfil < filter_pool && valid(name)) fil[++nfil] = name
  next
}
END {
  if (npop == 0) { print "gen-queryset: no usable popular names" > "/dev/stderr"; exit 2 }
  if (filter_pct > 0 && nfil == 0) { print "gen-queryset: no usable Filter names" > "/dev/stderr"; exit 2 }

  state = seed % 2147483647
  if (state == 0) state = 1
  for (i = 0; i < 10; i++) rnd()

  total = 0
  for (i = 1; i <= npop; i++) { total += 1 / (i ^ zipf); cum[i] = total }

  for (i = 1; i <= lines; i++) {
    u = rnd() * 100
    if (u < filter_pct) {
      name = fil[int(rnd() * nfil) + 1]
    } else if (u < filter_pct + nx_pct) {
      name = "n" int(rnd() * nx_pool) "." nx_suffix
    } else {
      t = rnd() * total; lo = 1; hi = npop
      while (lo < hi) { mid = int((lo + hi) / 2); if (cum[mid] < t) lo = mid + 1; else hi = mid }
      name = pop[lo]
    }
    q = rnd() * 100
    print name, (q < 60 ? "A" : (q < 90 ? "AAAA" : "HTTPS"))
  }
}' "$popular" "$filter"
