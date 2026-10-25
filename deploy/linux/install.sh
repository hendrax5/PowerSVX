#!/usr/bin/env bash
# Install PowerSVX on a Linux host (systemd).
# Run as root from a release tree that contains:
#   powersvx                 (linux amd64/arm64 binary)
#   web/dist/                (built UI)  OR  already at /usr/share/PowerSVX/web
#   configs/powersvx.linux.toml
#   configs/sample-blocklist.txt
#   deploy/linux/powersvx.service
#   deploy/linux/powersvx.env.example
#
# Usage:
#   sudo ./deploy/linux/install.sh
#   sudo ./deploy/linux/install.sh /path/to/powersvx-binary

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Default to Full Production High-QPS stack (Docker Host Mode) unless --standalone is requested
if [[ "${1:-}" != "--standalone" && -z "${1:-}" ]]; then
  echo "=========================================================================="
  echo " Installing Full PowerSVX Production Stack (Dnsdist + Unbound + Grafana) "
  echo "=========================================================================="
  exec bash "$ROOT/deploy/linux/bootstrap-node.sh"
fi

if [[ "${1:-}" == "--standalone" ]]; then
  shift
fi

BIN_SRC="${1:-}"
if [[ -z "$BIN_SRC" ]]; then
  if [[ -x "$ROOT/powersvx" ]]; then
    BIN_SRC="$ROOT/powersvx"
  elif [[ -x "$ROOT/bin/powersvx" ]]; then
    BIN_SRC="$ROOT/bin/powersvx"
  else
    echo "Build first: GOOS=linux GOARCH=amd64 go build -o powersvx ./cmd/powersvx" >&2
    echo "Or pass binary path: $0 /path/to/powersvx" >&2
    exit 1
  fi
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

id powersvx &>/dev/null || useradd --system --home-dir /var/lib/powersvx --shell /usr/sbin/nologin powersvx

install -d -m 0755 /etc/powersvx /etc/powersvx/certs /var/lib/powersvx /var/log/powersvx /usr/share/PowerSVX/web
install -m 0755 "$BIN_SRC" /usr/local/bin/powersvx

if [[ ! -f /etc/powersvx/powersvx.toml ]]; then
  install -m 0640 "$ROOT/configs/powersvx.linux.toml" /etc/powersvx/powersvx.toml
fi
if [[ ! -f /etc/powersvx/powersvx.env ]]; then
  install -m 0600 "$ROOT/deploy/linux/powersvx.env.example" /etc/powersvx/powersvx.env
  echo "EDIT /etc/powersvx/powersvx.env (PG_PASSWORD, API_TOKEN) before start."
fi
if [[ -f "$ROOT/configs/sample-blocklist.txt" ]]; then
  install -m 0644 "$ROOT/configs/sample-blocklist.txt" /etc/powersvx/sample-blocklist.txt
fi

if [[ -d "$ROOT/web/dist" ]]; then
  rm -rf /usr/share/PowerSVX/web/*
  cp -a "$ROOT/web/dist/." /usr/share/PowerSVX/web/
fi

# Self-signed TLS if missing (replace with real certs / ACME for production)
if [[ ! -f /etc/powersvx/certs/fullchain.pem ]]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
    -keyout /etc/powersvx/certs/privkey.pem \
    -out /etc/powersvx/certs/fullchain.pem \
    -subj "/CN=$(hostname -f 2>/dev/null || echo powersvx)" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null \
    || openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
      -keyout /etc/powersvx/certs/privkey.pem \
      -out /etc/powersvx/certs/fullchain.pem \
      -subj "/CN=powersvx"
  chmod 640 /etc/powersvx/certs/privkey.pem /etc/powersvx/certs/fullchain.pem
fi

chown -R powersvx:powersvx /var/lib/powersvx /var/log/powersvx /etc/powersvx
chown root:powersvx /etc/powersvx/powersvx.env /etc/powersvx/powersvx.toml
chmod 640 /etc/powersvx/powersvx.toml
chmod 600 /etc/powersvx/powersvx.env

install -m 0644 "$ROOT/deploy/linux/powersvx.service" /etc/systemd/system/powersvx.service
systemctl daemon-reload
systemctl enable powersvx.service

cat <<EOF

Installed.
  1. Ensure PostgreSQL DB/user PowerSVX exists (see deploy/linux/README.md)
  2. Edit secrets:  nano /etc/powersvx/powersvx.env
  3. Edit ACL/etc:   nano /etc/powersvx/powersvx.toml
  4. Start:          systemctl start powersvx
  5. Status:         systemctl status powersvx
  6. UI (local):     curl -s http://127.0.0.1:5380/api/v1/health
  7. Reload config flags: systemctl reload powersvx  (SIGHUP)

EOF
