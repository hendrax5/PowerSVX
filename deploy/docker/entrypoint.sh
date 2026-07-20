#!/bin/sh
# Ensure data dirs exist. Run as root so privileged ports (53/853/443) bind reliably.
set -e
mkdir -p /data/cache /var/log/PowerSVX /etc/PowerSVX/certs
exec "$@"
