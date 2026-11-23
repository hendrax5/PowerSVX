#!/bin/sh
# Validate the Unbound configuration before Unbound is created or recreated.
#
# Usage: deploy/linux/check-unbound-conf.sh [root]
#   root  the PowerSVX checkout (default: this script's checkout)
#
# Checks, in order, and stops at the first failure with the file it found the fault in:
#   1. configs/unbound/unbound.conf enables the control interface and includes the
#      Control Plane's runtime files, so the Control Plane can reload Unbound;
#   2. data/unbound-rpz/runtime-zones.conf has no forward-zone that points back into
#      the Dataplane (Unbound's own listener or dnsdist): Unbound would forward to
#      itself and answer SERVFAIL for every name outside the hosted zones;
#   3. unbound-checkconf in the pinned Unbound image accepts the whole configuration,
#      runtime files included.
# Exit 0 when all pass. Anything else means: do not start or recreate Unbound.
#
# POWERSVX_UNBOUND_IMAGE          image to check with (default: the one the host compose file runs)
# POWERSVX_UNBOUND_BACKEND_PORT   Unbound's listener port (default 5353)

set -u

ROOT="${1:-$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)}"
CONF="$ROOT/configs/unbound/unbound.conf"
RPZ="$ROOT/data/unbound-rpz"
ZONES="$RPZ/runtime-zones.conf"
IMAGE="${POWERSVX_UNBOUND_IMAGE:-mvance/unbound:1.22.0}" # keep in step with deploy/linux/docker-compose.host.yml
PORT="${POWERSVX_UNBOUND_BACKEND_PORT:-5353}"
INSIDE=/opt/unbound/etc/unbound

fail() {
  echo "check-unbound-conf: $*" >&2
  echo "check-unbound-conf: not touching Unbound. See docs/PRODUCTION.md, \"Unbound forwards to itself\"." >&2
  exit 1
}

[ -f "$CONF" ] || fail "$CONF does not exist; run deploy/linux/gen-unbound-conf.sh"

if ! grep -Eq '^[[:space:]]*control-enable:[[:space:]]*yes' "$CONF"; then
  fail "$CONF does not enable the control interface (control-enable: yes on 127.0.0.1); the Control Plane could not reload Unbound. Regenerate it with deploy/linux/gen-unbound-conf.sh"
fi
if ! grep -Eq '^[[:space:]]*include:[[:space:]]*.*rpz/runtime-zones\.conf' "$CONF"; then
  fail "$CONF does not include rpz/runtime-zones.conf; the Control Plane's zones would never load. Regenerate it with deploy/linux/gen-unbound-conf.sh"
fi

if [ -f "$ZONES" ]; then
  loops="$(awk -v port="$PORT" '
    /^[[:space:]]*forward-zone:/ { inzone = 1; next }
    /^[^[:space:]#]/ { inzone = 0 }
    inzone && /^[[:space:]]*forward-addr:/ {
      a = $0
      sub(/^[[:space:]]*forward-addr:[[:space:]]*/, "", a)
      sub(/[[:space:]]*(#.*)?$/, "", a)
      host = a; p = 53
      if (i = index(a, "@")) { host = substr(a, 1, i - 1); p = substr(a, i + 1) + 0 }
      else if (a ~ /^\[.*\]:[0-9]+$/) { host = a; sub(/\]:[0-9]+$/, "]", host); p = a; sub(/^.*\]:/, "", p); p += 0 }
      gsub(/[\[\]]/, "", host)
      if ((host ~ /^127\./ || host == "::1" || host == "0.0.0.0" || host == "::" || host == "localhost") && (p == port + 0 || p == 53))
        printf "%s:%d: forward-addr %s\n", FILENAME, FNR, a
    }
  ' "$ZONES")"
  if [ -n "$loops" ]; then
    printf '%s\n' "$loops" >&2
    fail "$ZONES forwards to Unbound itself or to dnsdist (listed above). Remove the forward-zone block, set the resolver mode to recursive with no forwarders, and reload Unbound"
  fi
fi

command -v docker >/dev/null 2>&1 || fail "docker is not available, so the configuration cannot be checked with unbound-checkconf"

# Check a copy inside a container that never starts Unbound: no bind mounts, so it works
# against a remote Docker daemon as well, and it sees the same layout Unbound will.
# The image creates var/root.key at start with unbound-anchor (the built-in anchor is used when it cannot update); checkconf needs it to exist.
cid="$(docker create --entrypoint sh "$IMAGE" -c "mkdir -p $INSIDE/var; unbound-anchor -a $INSIDE/var/root.key >/dev/null 2>&1; exec unbound-checkconf $INSIDE/unbound.conf")" || fail "cannot create a container from $IMAGE"
trap 'docker rm -f -v "$cid" >/dev/null 2>&1' EXIT
docker cp "$CONF" "$cid:$INSIDE/unbound.conf" >/dev/null || fail "cannot copy $CONF into the check container"
if [ -d "$RPZ" ]; then
  docker cp "$RPZ/." "$cid:$INSIDE/rpz" >/dev/null || fail "cannot copy $RPZ into the check container"
fi
if ! out="$(docker start -a "$cid" 2>&1)"; then
  printf '%s\n' "$out" >&2
  fail "unbound-checkconf rejected the configuration (file and line are above; $INSIDE/unbound.conf is $CONF and $INSIDE/rpz is $RPZ)"
fi
echo "check-unbound-conf: ok ($(printf '%s' "$out" | tail -n1))"
