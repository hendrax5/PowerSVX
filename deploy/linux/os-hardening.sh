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

# Bypass conntrack for DNS UDP traffic to eliminate conntrack CPU overhead and prevent table overflow
if command -v iptables &>/dev/null; then
  echo "==> Configuring iptables NOTRACK on UDP port 53..."
  iptables -t raw -C PREROUTING -p udp --dport 53 -j NOTRACK 2>/dev/null || \
    iptables -t raw -A PREROUTING -p udp --dport 53 -j NOTRACK 2>/dev/null || true
  iptables -t raw -C OUTPUT -p udp --sport 53 -j NOTRACK 2>/dev/null || \
    iptables -t raw -A OUTPUT -p udp --sport 53 -j NOTRACK 2>/dev/null || true
fi

# Maximize NIC ring buffers if ethtool is available
if command -v ethtool &>/dev/null; then
  DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1 || true)
  if [[ -n "$DEFAULT_IFACE" ]]; then
    echo "==> Tuning NIC ring buffer on $DEFAULT_IFACE..."
    ethtool -G "$DEFAULT_IFACE" rx 4096 tx 4096 2>/dev/null || true
  fi
fi

# Display current conntrack & socket buffer limits
echo "==> Current conntrack limits:"
sysctl net.netfilter.nf_conntrack_max 2>/dev/null || true
sysctl net.netfilter.nf_conntrack_count 2>/dev/null || true
echo "==> Current socket buffers:"
sysctl net.core.rmem_max 2>/dev/null || true

echo "==> PowerSVX OS hardening applied successfully."
