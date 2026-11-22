#!/bin/sh
# Refuse to continue when this node is configured for a Dataplane mode that is
# removed or being removed. Only the dnsdist Dataplane has a future.
#
# Usage: sh deploy/linux/dataplane-guard.sh [ROOT]
#   Reads POWERSVX_DNS_DATAPLANE from the environment, then from ROOT/.env (as
#   docker compose does). Unset means dnsdist, as on a host deployment.
#
#   unbound, external  The Unbound-on-the-public-port mode was removed. No code
#                      remains to run it, so nothing skips this check.
#   anything else      (the Go resolver) is being removed in the next major
#                      version. POWERSVX_ALLOW_LEGACY_DATAPLANE=1 lets a lab skip
#                      the check until then.
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
    echo "POWERSVX_DNS_DATAPLANE=$mode is configured, but the Unbound-on-the-public-port Dataplane mode has been removed, and POWERSVX_ALLOW_LEGACY_DATAPLANE does not bring it back. PowerSVX supports only the dnsdist Dataplane, with Unbound as its recursive backend behind dnsdist. Move this node to the dnsdist Dataplane (POWERSVX_DNS_DATAPLANE=dnsdist); see docs/PRODUCTION.md." >&2
    exit 1
    ;;
esac

if [ "${POWERSVX_ALLOW_LEGACY_DATAPLANE:-}" = "1" ]; then
  echo "WARNING: POWERSVX_ALLOW_LEGACY_DATAPLANE=1, continuing with the $mode Dataplane (labs only)." >&2
  exit 0
fi

echo "POWERSVX_DNS_DATAPLANE=$mode is configured, but this Dataplane mode is being removed in the next major version of PowerSVX, which supports only the dnsdist Dataplane. Move this node to the dnsdist Dataplane (POWERSVX_DNS_DATAPLANE=dnsdist) before updating; see docs/PRODUCTION.md." >&2
exit 1
