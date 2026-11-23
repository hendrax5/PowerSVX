#!/bin/sh
# Watchtower health check: reads Watchtower's recent log and reports, as a
# WARNING with the fix, the signs that it cannot pull the image (and so never
# updates this node) even though its session line says failed=0.
# Always exits 0; it must never fail an update.
#
# Usage: sh deploy/linux/watchtower-health.sh
#   POWERSVX_WATCHTOWER_CONTAINER  container name (default powersvx-watchtower)
#   WATCHTOWER_LOG_SINCE           how far back to read (default 72h)
#
# Note: recreating the container (apply-update.sh does) starts a new log, so run
# this before the recreate, or after the next scheduled run.
name="${POWERSVX_WATCHTOWER_CONTAINER:-powersvx-watchtower}"
since="${WATCHTOWER_LOG_SINCE:-72h}"

if ! log="$(docker logs --since "$since" "$name" 2>&1)"; then
  echo "WARNING: watchtower: container $name was not found or its log cannot be read; this node is not auto-updating until Watchtower runs (docker compose up -d watchtower)."
  exit 0
fi

bad="$(printf '%s\n' "$log" | grep -iE 'unauthorized|status 401|401 Unauthorized|denied|Could not pull image' | tail -n 3 | cut -c1-300)"
empty="$(printf '%s\n' "$log" | grep -iE 'scanned=0([^0-9]|$)' | tail -n 1 | cut -c1-300)"

if [ -n "$bad" ] || [ -n "$empty" ]; then
  echo "WARNING: watchtower: cannot pull the image, so this node does NOT auto-update (its session line still says failed=0)."
  [ -n "$bad" ] && printf '  log: %s\n' "$bad"
  [ -n "$empty" ] && printf '  log: %s\n' "$empty"
  echo "  Fix: make the GitHub package public, or give Watchtower a registry login:"
  echo "  a token with read:packages in .env (GHCR_USER, GHCR_TOKEN) or 'sudo docker login ghcr.io', then re-run apply-update.sh."
  echo "  See docs/PRODUCTION.md, \"Watchtower and the private GHCR image\"."
  exit 0
fi

if printf '%s\n' "$log" | grep -qiE 'Session done|Update session completed|Found new|No updates'; then
  echo "watchtower: OK, no registry errors in the last $since."
else
  echo "watchtower: no update session in the log of the last $since yet (the log restarts when the container is recreated; the next one runs on schedule)."
fi
exit 0
