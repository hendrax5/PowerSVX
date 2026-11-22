#!/bin/sh
# Refuse to continue when this node is configured for a Dataplane mode that no
# longer exists. Only the dnsdist Dataplane remains.
#
# Usage: sh deploy/linux/dataplane-guard.sh [ROOT]
#   Reads POWERSVX_DNS_DATAPLANE from the environment, then from ROOT/.env (as
#   docker compose does). Unset means dnsdist.
#
#   unbound, external  The Unbound-on-the-public-port mode was removed.
#   anything else      The Go resolver mode was removed.
#
# Nothing skips this check; POWERSVX_ALLOW_LEGACY_DATAPLANE has no effect.
#
# The messages below are the same sentences the Control Plane prints
# (internal/config/dataplane.go); a test keeps them equal.
ROOT="${1:-.}"

mode="${POWERSVX_DNS_DATAPLANE:-}"
if [ -z "$mode" ] && [ -f "$ROOT/.env" ]; then
  mode="$(grep -E '^POWERSVX_DNS_DATAPLANE=' "$ROOT/.env" | tail -n 1 | cut -d= -f2- | tr -d "\"'\r" || true)"
fi
mode="$(printf '%s' "${mode:-dnsdist}" | tr 'A-Z' 'a-z' | tr -d ' \t')"

case "$mode" in
  dnsdist|cdb) exit 0 ;;
  unbound|external)
    echo "POWERSVX_DNS_DATAPLANE=$mode is configured, but the Unbound-on-the-public-port Dataplane mode has been removed. PowerSVX supports only the dnsdist Dataplane, with Unbound as its recursive backend behind dnsdist. Move this node to the dnsdist Dataplane (POWERSVX_DNS_DATAPLANE=dnsdist); see docs/PRODUCTION.md." >&2
    exit 1
    ;;
esac

echo "POWERSVX_DNS_DATAPLANE=$mode is configured, but the Go resolver Dataplane mode has been removed. PowerSVX supports only the dnsdist Dataplane, with Unbound as its recursive backend behind dnsdist. Move this node to the dnsdist Dataplane (POWERSVX_DNS_DATAPLANE=dnsdist); see docs/PRODUCTION.md." >&2
exit 1
