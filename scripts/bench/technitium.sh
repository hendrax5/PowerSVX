#!/usr/bin/env bash
# Run Technitium DNS Server as the comparison system for the Reference Load benchmark,
# in a configuration chosen to be fair to PowerSVX.
#
# Usage (needs Docker, curl, and root or docker group membership):
#   technitium.sh up -f FILTER -a NETWORKS [options]
#   technitium.sh settings         print the settings the server is actually running with, as JSON
#   technitium.sh down             stop and remove the container (the state directory is kept)
#
# Options for up:
#   -f FILE      Filter names, the same file given to gen-queryset.sh -f (required)
#   -a NETWORKS  comma-separated CIDRs allowed to use recursion (required; there is
#                no open-resolver default). Example: the load generator's address /32
#   -b ADDRESS   address to listen on (default: all addresses)
#   -P PORT      DNS port (default 53)
#   -N MODE      host (default) or bridge. bridge publishes the DNS port on -b (default
#                127.0.0.1) and is meant for functional checks, not for measurements
#   -z SIZE      full (default) or small. small places the container in powersvx-bench.slice,
#                created by size-slice.sh, so it is held to the same CPUs and memory as the
#                PowerSVX stack
#   -t TAG       image tag (default: the pinned release below)
#   -c ENTRIES   cache size in entries (default 1000000)
#   -S V4,V6     sinkhole addresses for blocked names (default 139.255.196.196,::, the same
#                as PowerSVX's POWERSVX_SPOOF_IPV4 / POWERSVX_SPOOF_IPV6)
#   -w PORT      web console port, bound to 127.0.0.1 (default 5380)
#   -d DIR       state directory (default ./technitium-state)
#   -T SECONDS   how long to wait for the Filter to load (default 900)
#
# The configuration, and why:
#   recursion          full recursive resolution from the root servers, no forwarders, as
#                      PowerSVX's Unbound does. Allowed only for -a, never open.
#   blocking           the Filter names as a block list, answered with the sinkhole addresses:
#                      A -> V4, AAAA -> V6, other types NOERROR with no data. This is what the
#                      dnsdist rules do. Names match their subdomains in both systems.
#   query logging      off (logQueries=false). Dashboard statistics stay at their default.
#   cache              1,000,000 entries (the default of 10,000 cannot hold the query set) and a
#                      minimum record TTL of 60 s, matching dnsdist's packet cache (minTTL=60).
#                      Everything else is left at the release's defaults.
#   web console        127.0.0.1 only; the admin password is generated into the state directory
#                      and never printed.

set -euo pipefail

TECHNITIUM_TAG_DEFAULT="15.6.2"
NAME="technitium-bench"
SLICE=powersvx-bench.slice

die() { echo "technitium: $*" >&2; exit 2; }
log() { echo "technitium: $*" >&2; }

cmd="${1:-}"
[ -n "$cmd" ] || die "usage: technitium.sh up|settings|down (see the header of this script)"
shift

filter="" acl="" bind="" port=53 mode=host size=full tag="$TECHNITIUM_TAG_DEFAULT"
cache=1000000 sinkhole="139.255.196.196,::" web=5380 state="./technitium-state" wait_s=900
while getopts "f:a:b:P:N:z:t:c:S:w:d:T:" opt; do
  case "$opt" in
    f) filter="$OPTARG" ;;
    a) acl="$OPTARG" ;;
    b) bind="$OPTARG" ;;
    P) port="$OPTARG" ;;
    N) mode="$OPTARG" ;;
    z) size="$OPTARG" ;;
    t) tag="$OPTARG" ;;
    c) cache="$OPTARG" ;;
    S) sinkhole="$OPTARG" ;;
    w) web="$OPTARG" ;;
    d) state="$OPTARG" ;;
    T) wait_s="$OPTARG" ;;
    *) die "unknown option (see the header of this script)" ;;
  esac
done

[[ "$port" =~ ^[0-9]+$ ]] || die "-P must be a port number"
[[ "$web" =~ ^[0-9]+$ ]] || die "-w must be a port number"
[[ "$cache" =~ ^[1-9][0-9]*$ ]] || die "-c must be a positive whole number"
[[ "$wait_s" =~ ^[0-9]+$ ]] || die "-T must be a whole number of seconds"
[[ "$tag" =~ ^[A-Za-z0-9._-]+$ ]] || die "-t is not a valid image tag"
case "$mode" in host | bridge) ;; *) die "-N must be host or bridge" ;; esac
case "$size" in full | small) ;; *) die "-z must be full or small" ;; esac
IFS=, read -r sink4 sink6 <<<"$sinkhole"
[ -n "${sink4:-}" ] && [ -n "${sink6:-}" ] || die "-S needs two addresses: V4,V6"
[[ "$sink4" =~ ^[0-9.]+$ ]] || die "-S: '$sink4' is not an IPv4 address"
[[ "$sink6" =~ ^[0-9a-fA-F:]+$ ]] || die "-S: '$sink6' is not an IPv6 address"

IMAGE="technitium/dns-server:$tag"
mkdir -p "$state"
state="$(cd "$state" && pwd)"
pwfile="$state/admin-password"
hdr=""
cleanup() { [ -n "$hdr" ] && rm -f "$hdr"; true; }
trap cleanup EXIT

# --- API helpers -------------------------------------------------------------
web_base="http://127.0.0.1:$web"

login() {
  [ -s "$pwfile" ] || die "no admin password at $pwfile; run 'up' first"
  local reply token
  reply="$(curl -sS -m 15 --data-urlencode "user=admin" --data-urlencode "pass@$pwfile" "$web_base/api/user/login")" ||
    die "the web console is not reachable on $web_base"
  case "$reply" in *'"status":"ok"'*) ;; *) die "login to the web console failed" ;; esac
  token="$(printf '%s' "$reply" | sed -E 's/.*"token":"([^"]+)".*/\1/')"
  hdr="$(mktemp)"
  chmod 600 "$hdr"
  printf 'Authorization: Bearer %s\n' "$token" >"$hdr"
}

api() { # path [curl args...]; the token travels in a header file, not on the command line
  local path="$1"
  shift
  curl -sS -m 60 -H "@$hdr" "$@" "$web_base$path"
}

api_ok() {
  local out
  out="$(api "$@")" || die "request to $1 failed"
  case "$out" in *'"status":"ok"'*) ;; *) die "request to $1 was refused: $(printf '%s' "$out" | head -c 200)" ;; esac
}

settings_json() {
  local raw key
  raw="$(api /api/settings/get)"
  printf '{\n  "image": "%s",\n  "image_digest": "%s"' "$IMAGE" \
    "$(docker image inspect "$IMAGE" --format '{{index .RepoDigests 0}}' 2>/dev/null || echo unknown)"
  for key in version recursion cacheMaximumEntries cacheMinimumRecordTtl cacheMaximumRecordTtl \
    cacheNegativeRecordTtl serveStale enableBlocking blockingType logQueries loggingType \
    maxConcurrentResolutionsPerCore udpPayloadSize enableInMemoryStats; do
    printf ',\n  "%s": %s' "$key" "$(printf '%s' "$raw" | grep -oE "\"$key\":(\"[^\"]*\"|[^,}\\[]+)" | head -1 | sed -E 's/^[^:]+://')"
  done
  for key in forwarders recursionNetworkACL customBlockingAddresses blockListUrls dnsServerLocalEndPoints; do
    printf ',\n  "%s": %s' "$key" "$(printf '%s' "$raw" | grep -oE "\"$key\":(\\[[^]]*\\]|null|\"[^\"]*\")" | head -1 | sed -E 's/^[^:]+://')"
  done
  printf ',\n  "blocklist_names_loaded": %s\n}\n' "$(blocklist_count)"
}

blocklist_count() {
  api "/api/dashboard/stats/get?type=LastHour" | grep -oE '"blockListZones":[0-9]+' | head -1 | sed -E 's/.*://' || echo 0
}

resolve() { # name type -> prints the JSON of the answer from the server itself
  api "/api/dnsClient/resolve?server=${verify_addr}:${port}&domain=$1&type=$2"
}

# --- commands ----------------------------------------------------------------
case "$cmd" in
  down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    log "$NAME removed (state kept in $state)"
    ;;

  settings)
    docker inspect "$NAME" >/dev/null 2>&1 || die "$NAME is not running"
    login
    settings_json
    ;;

  up)
    [ -n "$filter" ] || die "-f Filter names file is required"
    [ -s "$filter" ] || die "Filter names file '$filter' is missing or empty"
    [ -n "$acl" ] || die "-a networks allowed to recurse is required (no open resolver)"
    [[ "$acl" =~ ^[0-9a-fA-F:./,]+$ ]] || die "-a must be a comma-separated list of CIDRs"
    command -v docker >/dev/null 2>&1 || die "docker is required"
    command -v curl >/dev/null 2>&1 || die "curl is required"
    if docker inspect "$NAME" >/dev/null 2>&1; then
      die "$NAME already exists; run 'technitium.sh down' first so a run never mixes configurations"
    fi
    # systemd creates a slice's cgroup only when something joins it, so ask systemd, not the filesystem.
    if [ "$size" = small ] && [ "$(systemctl is-active "$SLICE" 2>/dev/null || true)" != active ]; then
      die "$SLICE is not running; create it with: sudo size-slice.sh up"
    fi
    if [ "$mode" = host ] && command -v ss >/dev/null 2>&1; then
      busy="$(ss -H -lunt "sport = :$port" 2>/dev/null | head -1 || true)"
      [ -z "$busy" ] || die "port $port is already in use on this host: $busy"
    fi
    verify_addr="${bind:-127.0.0.1}"

    log "preparing the Filter ($(wc -l <"$filter" | tr -d ' ') lines)"
    LC_ALL=C awk '{
        sub(/\r$/, ""); gsub(/^[ \t]+|[ \t]+$/, "")
        if ($0 == "" || $0 ~ /^#/) next
        sub(/^\*\./, ""); sub(/\.$/, ""); $0 = tolower($0)
        if ($0 ~ /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/) print
      }' "$filter" | LC_ALL=C sort -u -T "$state" >"$state/blocklist.txt"
    expected="$(wc -l <"$state/blocklist.txt" | tr -d ' ')"
    [ "$expected" -gt 0 ] || die "no usable names in $filter"
    # first Filter name that is a valid host name: feeds hold a few junk entries (for example a leading hyphen) that a resolver rejects
    probe_name="$(grep -m1 -E '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' "$state/blocklist.txt")"
    [ -n "$probe_name" ] || die "no valid host name in the Filter file to check with"

    if [ ! -s "$pwfile" ]; then
      umask 077
      printf '%s' "$( (openssl rand -hex 16 2>/dev/null) || (head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'))" >"$pwfile"
    fi
    chmod 600 "$pwfile"
    mkdir -p "$state/config"

    run=(docker run -d --name "$NAME" --restart no
      -v "$state/config:/etc/dns"
      -v "$state/blocklist.txt:/filter/blocklist.txt:ro"
      -v "$pwfile:/run/secrets/admin-password:ro"
      -e DNS_SERVER_DOMAIN=technitium-bench.local
      -e DNS_SERVER_ADMIN_PASSWORD_FILE=/run/secrets/admin-password
      -e DNS_SERVER_RECURSION=UseSpecifiedNetworkACL
      -e "DNS_SERVER_RECURSION_NETWORK_ACL=$acl"
      -e DNS_SERVER_ENABLE_BLOCKING=true)
    if [ "$mode" = host ]; then
      run+=(--network host
        -e DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1
        -e "DNS_SERVER_WEB_SERVICE_HTTP_PORT=$web")
    else
      pub="${bind:-127.0.0.1}"
      run+=(-p "127.0.0.1:$web:5380" -p "$pub:$port:53/udp" -p "$pub:$port:53/tcp")
    fi
    [ "$size" = small ] && run+=(--cgroup-parent "$SLICE")
    run+=("$IMAGE")

    log "starting $IMAGE ($mode network, $size size)"
    "${run[@]}" >/dev/null

    for _ in $(seq 1 60); do
      curl -s -m 2 -o /dev/null "$web_base/" 2>/dev/null && break
      sleep 2
    done
    login

    # Settings are applied through the API, one request, so the state is explicit and can be read back.
    args=(--data-urlencode "recursion=UseSpecifiedNetworkACL"
      --data-urlencode "recursionNetworkACL=$acl"
      --data-urlencode "forwarders=false"
      --data-urlencode "enableBlocking=true"
      --data-urlencode "blockingType=CustomAddress"
      --data-urlencode "customBlockingAddresses=$sink4,$sink6"
      --data-urlencode "blockListUrls=file:///filter/blocklist.txt"
      --data-urlencode "logQueries=false"
      --data-urlencode "cacheMaximumEntries=$cache"
      --data-urlencode "cacheMinimumRecordTtl=60")
    if [ "$mode" = host ] && { [ -n "$bind" ] || [ "$port" != 53 ]; }; then
      args+=(--data-urlencode "dnsServerLocalEndPoints=${bind:-0.0.0.0}:$port")
    fi
    api_ok /api/settings/set "${args[@]}"
    api_ok /api/settings/forceUpdateBlockLists

    log "waiting for the Filter to load ($expected names)"
    loaded=0
    deadline=$((SECONDS + wait_s))
    stable=0
    last=-1
    while [ "$SECONDS" -lt "$deadline" ]; do
      loaded="$(blocklist_count)"
      loaded="${loaded:-0}"
      if [ "$loaded" -gt 0 ] && [ "$loaded" = "$last" ]; then stable=$((stable + 1)); else stable=0; fi
      last="$loaded"
      [ "$stable" -ge 3 ] && break
      sleep 5
    done
    [ "$stable" -ge 3 ] || die "the Filter did not finish loading within ${wait_s}s (loaded $loaded of $expected)"
    log "Filter loaded: $loaded names from $expected"
    awk -v l="$loaded" -v e="$expected" 'BEGIN { exit !(l < e * 0.99) }' &&
      log "WARNING: fewer names loaded than were given; some entries were rejected or merged"

    log "checking behaviour through the server itself"
    blocked="$(resolve "$probe_name" A)"
    case "$blocked" in
      *'"RCODE":"NoError"'*"\"IPAddress\":\"$sink4\""*) ;;
      *) die "$probe_name is in the Filter but was not answered with the sinkhole $sink4" ;;
    esac
    blocked6="$(resolve "$probe_name" AAAA)"
    case "$blocked6" in *'"IPAddress":"'*) ;; *) die "$probe_name AAAA was not answered with the sinkhole" ;; esac
    real="$(resolve example.com A)"
    case "$real" in
      *'"RCODE":"NoError"'*'"IPAddress":"'*) ;;
      *) die "example.com did not resolve; recursion from the root servers is not working" ;;
    esac
    bash "$(dirname "$0")/../../deploy/linux/dns-ready.sh" -s "$verify_addr" -p "$port" -t 3 -u invalid ||
      die "the DNS port does not answer from outside the container"

    log "ready: $IMAGE listening on ${bind:-all addresses}:$port; admin password is in $pwfile"
    ;;

  *) die "unknown command '$cmd'" ;;
esac
