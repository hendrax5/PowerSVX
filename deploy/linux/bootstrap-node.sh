#!/usr/bin/env bash
# ==============================================================================
# PowerSVX — Turnkey Fresh Node Bootstrap (Docker Host Mode, >10k QPS Ready)
# 
# Components deployed:
#   1. dnsdist (Port 53 public front-end + CDB blocklist mmap)
#   2. unbound (Port 5353 loopback recursive resolver)
#   3. powersvx (Port 5380 Web UI + REST API control-plane)
#   4. postgres (Port 5433 query-log history)   [Observability Profile]
#   5. prometheus (Port 9091 metrics aggregator)   [Observability Profile]
#   6. grafana (Port 3000 auto-provisioned dashboards embedded in UI)   [Observability Profile]
#   7. node-exporter (Port 9101 host telemetry)   [Observability Profile]
#
# POWERSVX_PROFILE=core starts only the Core Profile; hosts under 4 GB of memory
# select it automatically. See deploy/linux/select-profile.sh.
# ==============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
sh "$ROOT/deploy/linux/dataplane-guard.sh" "$ROOT" || exit 1
cd "$ROOT"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[-] Please run as root (or with sudo)." >&2
  exit 1
fi

echo "============================================================"
echo " PowerSVX Production Bootstrap — High-Throughput (>10k QPS) "
echo "============================================================"

# 1. Ensure Docker is installed and running
echo "==> [1/7] Checking Docker Engine..."
if ! command -v docker &>/dev/null; then
  echo "    Docker not found. Installing docker.io & compose plugin..."
  apt-get update -y
  apt-get install -y docker.io docker-compose-v2
fi

systemctl enable --now docker
echo "    Docker is active and running."

# 2. Stop conflicting services on port 53 (bare-metal powersvx or systemd-resolved)
echo "==> [2/7] Freeing Port 53 from host conflicts..."
if systemctl is-active --quiet powersvx 2>/dev/null; then
  echo "    Stopping legacy standalone powersvx.service..."
  systemctl stop powersvx
  systemctl disable powersvx || true
fi

# Disable systemd-resolved DNSStubListener if it's binding to port 53
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  if grep -q "DNSStubListener=no" /etc/systemd/resolved.conf 2>/dev/null; then
    :
  else
    echo "    Disabling systemd-resolved port 53 stub listener..."
    mkdir -p /etc/systemd/resolved.conf.d/
    cat > /etc/systemd/resolved.conf.d/powersvx-disable-stub.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
    systemctl restart systemd-resolved || true
  fi
fi

# 3. Apply Kernel & OS Hardening for >10k QPS (Conntrack & Buffers)
echo "==> [3/7] Applying OS & Kernel Hardening (Conntrack, Socket Buffers)..."
if [[ -f "$ROOT/deploy/linux/os-hardening.sh" ]]; then
  chmod +x "$ROOT/deploy/linux/os-hardening.sh"
  bash "$ROOT/deploy/linux/os-hardening.sh"
fi

# 4. Initialize Data Directories & Permissions
echo "==> [4/7] Preparing directories & permissions..."
mkdir -p data/postgres data/blocklist data/dnstap data/unbound-rpz data/unbound-logs configs/unbound configs/dnsdist
# PostgreSQL alpine uses UID 70
chown -R 70:70 data/postgres 2>/dev/null || true

# Auto-generate secure random secrets if .env does not exist
if [[ ! -f ".env" ]]; then
  echo "    Generating strong random secrets in .env..."
  PG_PASS=$(openssl rand -hex 16 2>/dev/null || echo "psvx_pg_$(date +%s)")
  API_TOK=$(openssl rand -hex 24 2>/dev/null || echo "psvx_api_$(date +%s)")
  GRAF_PASS=$(openssl rand -hex 16 2>/dev/null || echo "psvx_graf_$(date +%s)")
  cat > .env <<EOF
PG_PASSWORD=${PG_PASS}
API_TOKEN=${API_TOK}
GRAFANA_USER=admin
GRAFANA_PASSWORD=${GRAF_PASS}
EOF
  chmod 600 .env
fi

# dnsdist web password and API key: created here for a new .env, and for an existing one that lacks them.
sh "$ROOT/deploy/linux/ensure-dnsdist-credentials.sh" "$ROOT/.env"
for k in POWERSVX_DNSDIST_WEB_PASSWORD POWERSVX_DNSDIST_API_KEY; do
  if [[ -z "${!k:-}" ]]; then
    export "$k=$(grep -E "^$k=" "$ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d "\"'")"
  fi
done

# Seed bank whitelist if missing
if [[ ! -f "data/blocklist/banks.lua" ]]; then
  echo "whitelistSMN = newSuffixMatchNode()" > data/blocklist/banks.lua
  echo "whitelistSMN:add(newDNSName('bca.co.id.'))" >> data/blocklist/banks.lua
  echo "whitelistSMN:add(newDNSName('klikbca.com.'))" >> data/blocklist/banks.lua
  echo "whitelistSMN:add(newDNSName('bankmandiri.co.id.'))" >> data/blocklist/banks.lua
  echo "whitelistSMN:add(newDNSName('bri.co.id.'))" >> data/blocklist/banks.lua
  echo "whitelistSMN:add(newDNSName('bni.co.id.'))" >> data/blocklist/banks.lua
fi

# Seed CDB from repo if missing
if [[ ! -f "data/blocklist/domains.cdb" ]] || [[ ! -s "data/blocklist/domains.cdb" ]]; then
  echo "    Checking for repository blocklist seed..."
  mkdir -p data/blocklist
  if [[ -f "$ROOT/blocklist-seed.tgz" ]]; then
    echo "    Extracting default Kominfo sync seed from $ROOT/blocklist-seed.tgz..."
    tar -zxf "$ROOT/blocklist-seed.tgz" -C data/blocklist/ 2>/dev/null || true
    if [[ -f "data/blocklist/rpz-axfr-state.json" ]]; then
      cp "data/blocklist/rpz-axfr-state.json" "data/rpz-axfr-state.json" 2>/dev/null || true
    fi
  elif [[ -f "blocklist-seed.tgz" ]]; then
    echo "    Extracting default Kominfo sync seed from blocklist-seed.tgz..."
    tar -zxf "blocklist-seed.tgz" -C data/blocklist/ 2>/dev/null || true
    if [[ -f "data/blocklist/rpz-axfr-state.json" ]]; then
      cp "data/blocklist/rpz-axfr-state.json" "data/rpz-axfr-state.json" 2>/dev/null || true
    fi
  fi
  if [[ ! -f "data/blocklist/domains.cdb" ]]; then
    touch data/blocklist/domains.cdb
  fi
fi


# 5. Generate Unbound & dnsdist configurations sized to Host RAM/CPU
echo "==> [5/7] Auto-sizing Unbound & dnsdist configs from host specs..."
export POWERSVX_DNS_DATAPLANE=dnsdist
bash "$ROOT/deploy/linux/gen-unbound-conf.sh" "$ROOT/configs/unbound/unbound.conf"
bash "$ROOT/deploy/linux/gen-dnsdist-conf.sh" "$ROOT/configs/dnsdist/dnsdist.conf"

# Refuse to start Unbound on a configuration it would reject or that makes it forward to itself.
bash "$ROOT/deploy/linux/check-unbound-conf.sh" "$ROOT" || exit 1

if [[ -f "$ROOT/deploy/linux/calc-mem-env.sh" ]]; then
  # shellcheck disable=SC1091
  eval "$("$ROOT/deploy/linux/calc-mem-env.sh")"
  export POWERSVX_MEM_LIMIT GOMEMLIMIT POWERSVX_MEM_PERCENT
fi

# 6. Pull (or Build) and Start Full Docker Stack (including Watchtower, Grafana & Prometheus)
echo "==> [6/7] Starting Docker Compose stack (Host Networking)..."
export GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
export BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export POWERSVX_VERSION="${POWERSVX_VERSION:-2.0.0}"
export GOGC=50

GHCR_USER_VAL="${GHCR_USER:-}"
GHCR_TOKEN_VAL="${GHCR_TOKEN:-}"
if [[ -z "$GHCR_TOKEN_VAL" && -f "$ROOT/.env" ]]; then
  GHCR_USER_VAL="$(grep -E '^GHCR_USER=' "$ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d "\"'\r" || true)"
  GHCR_TOKEN_VAL="$(grep -E '^GHCR_TOKEN=' "$ROOT/.env" | tail -n1 | cut -d= -f2- | tr -d "\"'\r" || true)"
fi
if [[ -n "$GHCR_TOKEN_VAL" ]]; then
  echo "    Logging in to ghcr.io for private image pull..."
  printf '%s\n' "$GHCR_TOKEN_VAL" | docker login ghcr.io -u "${GHCR_USER_VAL:-hendrax5}" --password-stdin >/dev/null
fi
# Only warns; a node without registry credentials still installs, it just cannot auto-update.
sh "$ROOT/deploy/linux/registry-preflight.sh" "$ROOT" || true

PROFILE="$(sh "$ROOT/deploy/linux/select-profile.sh")" || exit 1
PROFILE_EXPLICIT=0
sh "$ROOT/deploy/linux/select-profile.sh" -x && PROFILE_EXPLICIT=1 || true
COMPOSE=(docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml)
if [[ "$PROFILE" == "core" ]]; then
  echo "    Core Profile: starting dnsdist, unbound, powersvx, watchtower only (no Postgres: query history needs the Observability Profile)."
  COMPOSE+=(-f deploy/linux/docker-compose.core.yml)
  # Persist an automatic choice so apply-update.sh keeps the same profile.
  if [[ "$PROFILE_EXPLICIT" == "0" ]]; then
    echo "POWERSVX_PROFILE=core" >> .env
    echo "    Saved POWERSVX_PROFILE=core to .env (remove it to return to full)."
  fi
fi

if [[ "${POWERSVX_BUILD_LOCAL:-0}" == "1" ]]; then
  "${COMPOSE[@]}" build powersvx
else
  "${COMPOSE[@]}" pull powersvx \
    || "${COMPOSE[@]}" build powersvx
fi
"${COMPOSE[@]}" up -d
# Only an explicit POWERSVX_PROFILE=core removes Observability containers; an automatic
# choice never touches containers that are already there.
if [[ "$PROFILE" == "core" && "$PROFILE_EXPLICIT" == "1" ]]; then
  "${COMPOSE[@]}" rm -sf node-exporter prometheus grafana
fi

# 7. Verification & Health Summary
echo "==> [7/7] Verifying services..."
READY_WAIT="${POWERSVX_READY_WAIT:-90}"
READY_NAME="${POWERSVX_READY_NAME:-example.com}"
ready_rc=0
# First the local path (dnsdist -> Unbound), then a fresh label under a real name, which
# only recursion can answer.
bash "$ROOT/deploy/linux/dns-ready.sh" -w "$READY_WAIT" -u invalid || ready_rc=$?
if [[ "$ready_rc" -eq 0 ]]; then
  bash "$ROOT/deploy/linux/dns-ready.sh" -w "$READY_WAIT" -r "$READY_NAME" || ready_rc=$?
fi

echo "------------------------------------------------------------"
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
echo "------------------------------------------------------------"

if [[ "$ready_rc" -ne 0 ]]; then
  echo "" >&2
  echo "[-] Node is NOT ready: port 53 did not answer within ${READY_WAIT}s." >&2
  echo "    Check: docker logs powersvx-dnsdist-1 ; docker logs powersvx-unbound-1" >&2
  exit 1
fi

echo ""
echo "[✓] Deployment Complete! Services are now live:"
echo "    - Public DNS (dnsdist):       Port 53 (UDP/TCP)"
echo "    - Backend Recursive (Unbound): Port 5353 (127.0.0.1)"
echo "    - PowerSVX Web UI & REST API: http://$(hostname -I | awk '{print $1}'):5380"
if [[ "$PROFILE" != "core" ]]; then
echo "    - Grafana Analytics:          http://$(hostname -I | awk '{print $1}'):3000 (auto-embedded)"
echo "    - Prometheus Metrics:         http://$(hostname -I | awk '{print $1}'):9091"
else
  echo "    - Profile: core (no Grafana, Prometheus or node-exporter)"
fi
echo ""
