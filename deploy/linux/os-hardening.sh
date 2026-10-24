#!/usr/bin/env bash
# PowerSVX Linux OS & Kernel Hardening for high-throughput DNS resolvers
# Run as root (or with sudo)
set -euo pipefail

echo "==> Configuring kernel modules & conntrack parameters..."
# Load nf_conntrack module at boot
echo "nf_conntrack" > /etc/modules-load.d/powersvx-conntrack.conf 2>/dev/null || true
echo "options nf_conntrack hashsize=750000" > /etc/modprobe.d/powersvx-conntrack.conf 2>/dev/null || true

# Write sysctl tuning profile
cat > /etc/sysctl.d/98-powersvx.conf <<'EOF'
# Conntrack capacity for high-QPS DNS
net.netfilter.nf_conntrack_max = 3000000
net.netfilter.nf_conntrack_buckets = 750000

# UDP / Socket buffer tuning to prevent packet drops (Recv-Q)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.core.netdev_max_backlog = 10000

# TCP resilience
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 8192
EOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/98-powersvx.conf 2>/dev/null || sysctl --system >/dev/null 2>&1 || true

# Display current conntrack & socket buffer limits
echo "==> Current conntrack limits:"
sysctl net.netfilter.nf_conntrack_max 2>/dev/null || true
sysctl net.netfilter.nf_conntrack_count 2>/dev/null || true
echo "==> Current socket buffers:"
sysctl net.core.rmem_max 2>/dev/null || true

echo "==> PowerSVX OS hardening applied successfully."
