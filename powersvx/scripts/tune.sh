#!/usr/bin/env bash
# Phase 4 kernel/runtime tuning for high-QPS DNS on Ubuntu bare metal / VPS.
# Run as root. Values are conservative starting points — validate under load.
set -euo pipefail

echo "[powersvx] applying UDP/network sysctls..."

sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.core.rmem_default=4194304
sysctl -w net.core.wmem_default=4194304

# NIC/backlog: absorb bursts before user space drains them.
sysctl -w net.core.netdev_max_backlog=250000
sysctl -w net.core.somaxconn=8192

# UDP memory pressure thresholds (pages).
sysctl -w net.ipv4.udp_mem="8388608 12582912 16777216"
sysctl -w net.ipv4.udp_rmem_min=16384
sysctl -w net.ipv4.udp_wmem_min=16384

# TCP fallback path (truncation spikes).
sysctl -w net.ipv4.tcp_max_syn_backlog=8192
sysctl -w net.ipv4.tcp_fin_timeout=15

echo "[powersvx] done. Persist by adding these to /etc/sysctl.d/99-powersvx.conf"
echo
echo "IRQ affinity / RPS-RFS (bare metal): spread NIC IRQs across cores, e.g."
echo "  - set /proc/irq/<irq>/smp_affinity_list per queue"
echo "  - echo <cpu-mask> > /sys/class/net/<nic>/queues/rx-*/rps_cpus"
echo "  - echo 32768 > /sys/class/net/<nic>/queues/rx-*/rps_flow_cnt"
echo
echo "Runtime: set 'workers' == real cores and 'gomaxprocs: 0' in the YAML."
