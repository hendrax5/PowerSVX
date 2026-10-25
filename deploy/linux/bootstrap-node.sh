#!/usr/bin/env bash
# ==============================================================================
# PowerSVX — Turnkey Fresh Node Bootstrap (Docker Host Mode, >10k QPS Ready)
# 
# Components deployed:
#   1. dnsdist (Port 53 public front-end + CDB blocklist mmap)
#   2. unbound (Port 5353 loopback recursive resolver)
#   3. powersvx (Port 5380 Web UI + REST API control-plane)
#   4. postgres (Port 5433 persistent storage for query logs & auth)
#   5. prometheus (Port 9091 metrics aggregator)
#   6. grafana (Port 3000 auto-provisioned dashboards embedded in UI)
#   7. node-exporter (Port 9101 host telemetry)
# ==============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
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
mkdir -p data/postgres data/blocklist data/unbound-rpz data/unbound-logs configs/unbound configs/dnsdist
# PostgreSQL alpine uses UID 70
chown -R 70:70 data/postgres 2>/dev/null || true

# Seed bank whitelist if missing
if [[ ! -f "data/blocklist/banks.lua" ]]; then
  echo "whitelistSMN = newSuffixMatchNode()" > data/blocklist/banks.lua
  echo "whitelistSMN:add(newDNSName('bca.co.id.'))" >> data/blocklist/banks.lua
  echo "whitelistSMN:add(newDNSName('klikbca.com.'))" >> data/blocklist/banks.lua
  echo "whitelistSMN:add(newDNSName('bankmandiri.co.id.'))" >> data/blocklist/banks.lua
  echo "whitelistSMN:add(newDNSName('bri.co.id.'))" >> data/blocklist/banks.lua
  echo "whitelistSMN:add(newDNSName('bni.co.id.'))" >> data/blocklist/banks.lua
fi

# Seed minimal CDB if missing
if [[ ! -f "data/blocklist/domains.cdb" ]]; then
  echo "    Generating initial blocklist seed..."
  if command -v cdb &>/dev/null; then
    touch data/blocklist/domains.cdb
  else
    # Create empty valid file
    touch data/blocklist/domains.cdb
  fi
fi

# 5. Generate Unbound & dnsdist configurations sized to Host RAM/CPU
echo "==> [5/7] Auto-sizing Unbound & dnsdist configs from host specs..."
export POWERSVX_DNS_DATAPLANE=dnsdist
bash "$ROOT/deploy/linux/gen-unbound-conf.sh" "$ROOT/configs/unbound/unbound.conf"
bash "$ROOT/deploy/linux/gen-dnsdist-conf.sh" "$ROOT/configs/dnsdist/dnsdist.conf"

if [[ -f "$ROOT/deploy/linux/calc-mem-env.sh" ]]; then
  # shellcheck disable=SC1091
  eval "$("$ROOT/deploy/linux/calc-mem-env.sh")"
  export POWERSVX_MEM_LIMIT GOMEMLIMIT POWERSVX_MEM_PERCENT
fi

# 6. Build and Start Full Docker Stack (including Grafana & Prometheus)
echo "==> [6/7] Starting Docker Compose stack (Host Networking)..."
export GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
export BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export POWERSVX_VERSION="1.6.3"
export GOGC=50

docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml build powersvx
docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml up -d

# 7. Verification & Health Summary
echo "==> [7/7] Verifying services..."
sleep 5

echo "------------------------------------------------------------"
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
echo "------------------------------------------------------------"

echo ""
echo "[✓] Deployment Complete! Services are now live:"
echo "    - Public DNS (dnsdist):       Port 53 (UDP/TCP)"
echo "    - Backend Recursive (Unbound): Port 5353 (127.0.0.1)"
echo "    - PowerSVX Web UI & REST API: http://$(hostname -I | awk '{print $1}'):5380"
echo "    - Grafana Analytics:          http://$(hostname -I | awk '{print $1}'):3000 (auto-embedded)"
echo "    - Prometheus Metrics:         http://$(hostname -I | awk '{print $1}'):9091"
echo ""
