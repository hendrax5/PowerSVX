#!/usr/bin/env bash
# Readiness check: exit 0 only when a DNS server answers a query.
#
# NOERROR and NXDOMAIN both count as an answer. No reply, SERVFAIL and REFUSED
# do not. Needs only bash and coreutils, so it runs inside the dnsdist
# container as well as on the host.
#
# Usage: dns-ready.sh [-s server] [-p port] [-t seconds] [-w seconds] [-u | -r] [name]
#   -s  server address (default 127.0.0.1)
#   -p  UDP port (default 53)
#   -t  seconds to wait for each reply (default 2)
#   -w  keep retrying for this many seconds before giving up (default 0: one try)
#   -u  prepend a fresh label to the name, so a cached answer cannot satisfy the check
#   -r  recursion check: -u, and refuse a name that a resolver answers by itself
#       (invalid, test, localhost, onion, ...). A fresh label under a real domain
#       such as example.com can only be answered by walking the DNS from the root,
#       so it fails when recursion is broken (for example a forwarder loop answers
#       SERVFAIL). It sends one real query upstream per run.
#   name defaults to example.com

set -u

server=127.0.0.1
port=53
reply_timeout=2
wait_total=0
unique=0
recursion=0

usage() {
  echo "usage: dns-ready.sh [-s server] [-p port] [-t seconds] [-w seconds] [-u | -r] [name]" >&2
}

while getopts "s:p:t:w:ur" opt; do
  case "$opt" in
    s) server="$OPTARG" ;;
    p) port="$OPTARG" ;;
    t) reply_timeout="$OPTARG" ;;
    w) wait_total="$OPTARG" ;;
    u) unique=1 ;;
    r) unique=1; recursion=1 ;;
    *) usage; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

base="${1:-example.com}"
base="${base%.}"

if [ "$recursion" = 1 ]; then
  case "$(printf %s "$base" | tr A-Z a-z)" in
    invalid|*.invalid|test|*.test|localhost|*.localhost|onion|*.onion|example|*.example|local|*.local|home.arpa|*.home.arpa|*.in-addr.arpa|*.ip6.arpa|"")
      echo "dns-ready: -r needs a name that is resolved by recursion, not answered locally: '$base'" >&2
      exit 2 ;;
  esac
fi

# Prints the query as printf %b escapes: header, QNAME, QTYPE A, QCLASS IN.
build_query() {
  local name="$1" id_hi="$2" id_lo="$3" label out
  out=$(printf '\\x%02x\\x%02x\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' "$id_hi" "$id_lo")
  local IFS=.
  for label in $name; do
    if [[ ! "$label" =~ ^[A-Za-z0-9_-]{1,63}$ ]]; then
      echo "dns-ready: unsupported label '$label' in '$name'" >&2
      return 1
    fi
    out+=$(printf '\\x%02x' "${#label}")$label
  done
  printf '%s' "$out"'\x00\x00\x01\x00\x01'
}

# One query, one verdict. Sets $reason on failure.
probe() {
  local name="$base" id_hi=$((RANDOM % 256)) id_lo=$((RANDOM % 256)) query reply b0 b1 b2 b3 rcode
  if [ "$unique" = 1 ]; then
    name="ready-$$-${RANDOM}${RANDOM}.${base}"
  fi
  query=$(build_query "$name" "$id_hi" "$id_lo") || exit 2

  if ! exec 3<>"/dev/udp/${server}/${port}"; then
    reason="cannot open a socket to ${server}:${port}"
    return 1
  fi
  # The query must leave in ONE datagram. bash's printf flushes at every 0x0a byte (an id or
  # label-length byte of 10), which would send two datagrams and the server would answer the
  # second one with a shifted header; so write it to a file and send that with a single write.
  printf '%b' "$query" >"$qfile"
  cat "$qfile" >&3
  reply=$(timeout "$reply_timeout" dd bs=512 count=1 <&3 2>/dev/null | od -An -tx1 -N4)
  exec 3>&-

  read -r b0 b1 b2 b3 <<<"$reply"
  if [ -z "${b3:-}" ]; then
    reason="no reply from ${server}:${port} for ${name}"
    return 1
  fi
  if [ "$((16#$b0))" -ne "$id_hi" ] || [ "$((16#$b1))" -ne "$id_lo" ] || [ $((16#$b2 & 0x80)) -eq 0 ]; then
    reason="unexpected reply from ${server}:${port} for ${name} (got ${b0} ${b1} ${b2} ${b3}, sent id ${id_hi} ${id_lo})"
    return 1
  fi
  rcode=$((16#$b3 & 0x0f))
  if [ "$rcode" -ne 0 ] && [ "$rcode" -ne 3 ]; then
    reason="${server}:${port} answered ${name} with rcode ${rcode}"
    if [ "$recursion" = 1 ]; then
      reason+=" (recursion is not working: check Unbound's forward-zone and that the node can reach the Internet)"
    fi
    return 1
  fi
  return 0
}

# Milliseconds since the epoch. $SECONDS is an integer that ticks at arbitrary moments, so a
# deadline computed from it can be up to a second short; this does not truncate.
now_ms() {
  if [ -n "${EPOCHREALTIME:-}" ]; then
    local t="${EPOCHREALTIME/[.,]/}"
    echo $((t / 1000))
  else
    echo $(($(date +%s) * 1000))
  fi
}

qfile="$(mktemp)" || { echo "dns-ready: cannot create a temporary file" >&2; exit 2; }
trap 'rm -f "$qfile"' EXIT

reason=""
deadline=$(($(now_ms) + wait_total * 1000))
while true; do
  if probe; then
    exit 0
  fi
  if [ "$(now_ms)" -ge "$deadline" ]; then
    echo "dns-ready: ${reason}" >&2
    exit 1
  fi
  sleep 1
done
