#!/bin/sh
# Registry preflight: tells the operator when this node has no way to pull the
# PowerSVX image from a private GHCR package, and so no way for Watchtower to
# auto-update it. It only warns. It always exits 0 and never fails an update.
#
# Usage: sh deploy/linux/registry-preflight.sh [ROOT]
#
# Two questions, both answered without printing any secret:
#   1. Can the image be pulled anonymously? (an anonymous token request, then a
#      manifest HEAD request, both with a timeout.) If yes, nothing else matters.
#   2. If not, does the Docker config that Watchtower gets (compose mounts
#      ${DOCKER_CONFIG_DIR:-/root/.docker} as /config) hold a login for ghcr.io?
#
# Settings are read from the environment, then ROOT/.env (as docker compose does):
#   POWERSVX_IMAGE, POWERSVX_IMAGE_TAG, DOCKER_CONFIG_DIR, GHCR_TOKEN (presence only).
# POWERSVX_REGISTRY_URL (default https://ghcr.io) exists for tests.
ROOT="${1:-.}"

envval() {
  eval "cur=\${$1:-}"
  if [ -n "$cur" ]; then printf '%s' "$cur"; return; fi
  if [ -f "$ROOT/.env" ]; then
    grep -E "^$1=" "$ROOT/.env" | tail -n 1 | cut -d= -f2- | tr -d "\"'\r"
  fi
}

image="$(envval POWERSVX_IMAGE)"; image="${image:-ghcr.io/hendrax5/powersvx}"
tag="$(envval POWERSVX_IMAGE_TAG)"; tag="${tag:-latest}"
cfgdir="$(envval DOCKER_CONFIG_DIR)"; cfgdir="${cfgdir:-/root/.docker}"
base="${POWERSVX_REGISTRY_URL:-https://ghcr.io}"

case "$image" in
  ghcr.io/*) repo="${image#ghcr.io/}" ;;
  *) exit 0 ;; # not GHCR: nothing to check here
esac

# 1. Anonymous pull.
anon=unknown
if command -v curl >/dev/null 2>&1; then
  resp="$(curl -sS -m 10 "$base/token?scope=repository:$repo:pull" 2>/dev/null || true)"
  tok="$(printf '%s' "$resp" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  code="000"
  if [ -n "$tok" ]; then
    code="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -I \
      -H "Authorization: Bearer $tok" \
      -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json' \
      "$base/v2/$repo/manifests/$tag" 2>/dev/null || true)"
  fi
  case "$code" in
    200) anon=yes ;;
    401|403|404) anon=no ;;
  esac
  tok=""
fi

if [ "$anon" = yes ]; then
  echo "registry: $image:$tag can be pulled anonymously; Watchtower needs no credentials."
  exit 0
fi
if [ "$anon" = unknown ]; then
  echo "registry: could not reach the registry to check whether $image is public (no network, or no curl); skipped."
  exit 0
fi

# 2. The login Watchtower will use.
problem=""
if [ ! -d "$cfgdir" ]; then
  problem="the directory $cfgdir (mounted into Watchtower as /config) does not exist, so Docker would create it empty"
elif [ ! -f "$cfgdir/config.json" ]; then
  problem="$cfgdir/config.json does not exist (nobody ran docker login on this host as the user that owns $cfgdir)"
elif ! grep -q 'ghcr\.io' "$cfgdir/config.json" 2>/dev/null; then
  problem="$cfgdir/config.json has no login for ghcr.io"
elif grep -q '"credsStore"' "$cfgdir/config.json" 2>/dev/null && ! grep -q '"auth"' "$cfgdir/config.json" 2>/dev/null; then
  problem="$cfgdir/config.json keeps the ghcr.io login in a credential helper, which the Watchtower container cannot run"
fi

if [ -z "$problem" ]; then
  echo "registry: $image is private and $cfgdir/config.json holds a ghcr.io login for Watchtower."
  exit 0
fi

tokenset="no"
[ -n "$(envval GHCR_TOKEN)" ] && tokenset="yes"
cat >&2 <<MSG
WARNING: Watchtower cannot authenticate to the registry, so this node will NOT auto-update.
  $image:$tag is not pullable anonymously (the package is private) and $problem.
  GHCR_TOKEN configured here: $tokenset.
  Fix it in one of two ways:
    1. Owner: make the GitHub package $image public (Package settings, Danger Zone,
       Change visibility). Nodes then need no credentials.
    2. Give this node a token with the read:packages scope only: put GHCR_USER and
       GHCR_TOKEN in $ROOT/.env and run apply-update.sh again, or run
       'sudo docker login ghcr.io -u <user>' (it asks for the token) on this host.
       The login must end up in $cfgdir/config.json (set DOCKER_CONFIG_DIR in .env if
       the login lives elsewhere), then recreate Watchtower:
       docker compose up -d --no-deps --force-recreate watchtower
  Details: docs/PRODUCTION.md, "Watchtower and the private GHCR image".
  This update continues.
MSG
exit 0
