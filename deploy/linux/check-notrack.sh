#!/usr/bin/env bash
# Operator check for ticket #23: does this node still carry the broad raw-table
# NOTRACK rule, and can a container on the default Docker bridge resolve by UDP?
#
#   check-notrack.sh [-u <upstream resolver IP>]
#
# Exit 0 when the broad rule is gone (and the bridge probe, if asked, passes),
# 1 when the broad rule is present or the probe fails, 2 when iptables is missing.
set -uo pipefail

upstream=""
while getopts "u:" o; do
  case "$o" in
    u) upstream="$OPTARG" ;;
    *) echo "usage: $0 [-u <upstream resolver IP>]" >&2; exit 2 ;;
  esac
done

command -v iptables >/dev/null 2>&1 || { echo "iptables not installed"; exit 2; }
rc=0

if iptables -t raw -C PREROUTING -p udp --dport 53 -j NOTRACK 2>/dev/null; then
  echo "FAIL broad rule present: run deploy/linux/notrack-dns.sh (or os-hardening.sh) as root"
  rc=1
else
  echo "OK   no broad PREROUTING NOTRACK rule"
fi
if iptables -t raw -C PREROUTING -p udp -m addrtype --dst-type LOCAL --dport 53 -j NOTRACK 2>/dev/null; then
  echo "OK   narrow rule present (Dataplane queries to this node stay untracked)"
else
  echo "WARN narrow rule missing: run deploy/linux/notrack-dns.sh as root"
fi

if [[ -n "$upstream" ]]; then
  if docker run --rm --entrypoint drill mvance/unbound:1.22.0 -Q -p 53 "@$upstream" example.org A >/dev/null 2>&1; then
    echo "OK   a container on the default bridge resolved example.org over UDP via $upstream"
  else
    echo "FAIL a container on the default bridge could not resolve via $upstream"
    rc=1
  fi
fi
exit "$rc"
