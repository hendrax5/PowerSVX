#!/usr/bin/env bash
# Publish blocklist-seed.tgz to GitHub Releases (from a synced host such as JMG).
#
# On the seed host (JMG), with a useful domains.cdb:
#   bash deploy/linux/publish-filter-seed.sh
#
# Env:
#   POWERSVX_DIR          default /home/hendra/powersvx
#   GH_REPO               default hendrax5/PowerSVX
#   SEED_TAG              default filter-seed
#   SEED_OUT              default /tmp/blocklist-seed.tgz
#   POWERSVX_API          default http://127.0.0.1:5380
#   POWERSVX_API_TOKEN     Bearer token (or admin session cookie via curl -b)
#
# New installs pull:
#   https://github.com/hendrax5/PowerSVX/releases/latest/download/blocklist-seed.tgz
# Override with POWERSVX_FILTER_SEED_URL.

set -euo pipefail

ROOT="${POWERSVX_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
API="${POWERSVX_API:-http://127.0.0.1:5380}"
OUT="${SEED_OUT:-/tmp/blocklist-seed.tgz}"
REPO="${GH_REPO:-hendrax5/PowerSVX}"
TAG="${SEED_TAG:-filter-seed}"

echo "==> export seed from $API"
AUTH=()
if [ -n "${POWERSVX_API_TOKEN:-}" ]; then
  AUTH=(-H "Authorization: Bearer ${POWERSVX_API_TOKEN}")
fi
curl -fsSL "${AUTH[@]}" "$API/api/v1/blocklist/seed" -o "$OUT"
ls -lah "$OUT"

if ! command -v gh >/dev/null 2>&1; then
  echo "Wrote $OUT — install GitHub CLI (gh) to upload, or attach manually to release '$TAG'."
  exit 0
fi

echo "==> upload to github.com/$REPO release $TAG"
if ! gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  gh release create "$TAG" "$OUT" \
    --repo "$REPO" \
    --title "Filter blocklist seed (CDB)" \
    --notes "Bootstrap domains.cdb for new PowerSVX installs. Refresh via IXFR from Komdigi after serial is set. Republish from JMG after major serial bumps."
else
  gh release upload "$TAG" "$OUT" --repo "$REPO" --clobber
fi
echo "done. Installs use: https://github.com/${REPO}/releases/latest/download/blocklist-seed.tgz"
