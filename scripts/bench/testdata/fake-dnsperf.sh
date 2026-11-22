#!/usr/bin/env bash
# Stands in for dnsperf in tests: a server that answers at most FAKE_CAPACITY
# queries per second, driven by a load generator that can send FAKE_FLOOD.
# Past its capacity the server drops queries; with FAKE_QUEUE=1 it answers them
# all late instead, which is how overload looks through dnsperf's outstanding limit.
rate=0
secs=1
while [ $# -gt 0 ]; do
  case "$1" in
    -h) echo "DNS Performance Testing Tool"; echo "Version 0.0.0-fake"; exit 0 ;;
    -Q) rate="$2"; shift ;;
    -l) secs="$2"; shift ;;
    -s|-p|-d|-c|-T|-q|-t|-O|-n) shift ;;
  esac
  shift
done
cap="${FAKE_CAPACITY:-5000}"
[ "$rate" -eq 0 ] && rate="${FAKE_FLOOD:-20000}"
sent=$((rate * secs))
completed="$sent"
fast="0.000256 - 0.000511"
slow="0.002048 - 0.004095"
if [ "$rate" -gt "$cap" ]; then
  if [ "${FAKE_QUEUE:-0}" = 1 ]; then
    # Nothing is lost; every answer arrives late.
    sent=$((cap * secs))
    completed="$sent"
    fast="0.032768 - 0.065535"
    slow="0.065536 - 0.131071"
  else
    completed=$((cap * secs))
  fi
fi
cat <<OUT
DNS Performance Testing Tool
Version 0.0.0-fake

Statistics:

  Queries sent:         $sent
  Queries completed:    $completed
  Queries lost:         $((sent - completed))

  Run time (s):         $secs.000000
  Queries per second:   $((completed / secs)).000000

  Average Latency (s):  0.000400 (min 0.000100, max 0.003000)
  Latency StdDev (s):   0.000100
  Latency bucket (s):   answer count
  $fast:  $((completed * 9 / 10))
  $slow:  $((completed - completed * 9 / 10))
OUT
