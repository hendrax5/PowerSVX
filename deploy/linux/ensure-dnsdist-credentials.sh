#!/bin/sh
# Make sure the env file holds a dnsdist web password and API key, creating random ones for
# whichever is missing or empty. Values already present are never touched.
#
#   sh deploy/linux/ensure-dnsdist-credentials.sh [env-file]      (default: <repo>/.env)
#
# Prints only which names it created, never a value. The file ends up mode 600.
# The same file is read by docker compose (Control Plane) and by apply-update.sh before it
# generates the dnsdist configuration, so both sides see the same values.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
FILE="${1:-$ROOT/.env}"
KEYS="POWERSVX_DNSDIST_WEB_PASSWORD POWERSVX_DNSDIST_API_KEY"

umask 077

random_hex() { # random_hex <bytes>
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1" 2>/dev/null && return 0
  fi
  head -c "$1" /dev/urandom | od -An -vtx1 | tr -d ' \n'
}

value_of() { # last assignment of a key, quotes and CR removed
  [ -f "$FILE" ] || return 0
  grep -E "^$1=" "$FILE" | tail -n 1 | cut -d= -f2- | tr -d "\"'\r" || true
}

missing=""
for k in $KEYS; do
  if [ -z "$(value_of "$k")" ]; then missing="$missing $k"; fi
done
if [ -z "$missing" ]; then
  echo "dnsdist web credentials already present in $FILE"
  exit 0
fi

TMP="$FILE.tmp.$$"
trap 'rm -f "$TMP"' EXIT INT TERM
: >"$TMP"
chmod 600 "$TMP"
if [ -f "$FILE" ]; then
  pattern=""
  for k in $missing; do pattern="$pattern${pattern:+|}$k"; done
  grep -vE "^($pattern)=" "$FILE" >"$TMP" || true
  if [ -s "$TMP" ] && [ -n "$(tail -c 1 "$TMP")" ]; then echo >>"$TMP"; fi
fi
for k in $missing; do
  case "$k" in
    *PASSWORD) n=16 ;;
    *) n=24 ;;
  esac
  v="$(random_hex "$n")"
  if [ "${#v}" -lt $((n * 2)) ]; then echo "could not read random bytes for $k" >&2; exit 1; fi
  printf '%s=%s\n' "$k" "$v" >>"$TMP"
  echo "created $k in $FILE"
done
chmod 600 "$TMP"
mv -f "$TMP" "$FILE"
trap - EXIT INT TERM
