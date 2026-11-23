#!/usr/bin/env bash
# Installs the conntrack bypass for DNS traffic of the Dataplane (ticket #23).
#
#   PREROUTING  udp dport 53, destination is an address of this node  -> NOTRACK
#   OUTPUT      udp sport 53                                          -> NOTRACK
#
# The PREROUTING rule used to match every UDP/53 packet. That includes packets a
# container on the default Docker bridge sends to an outside resolver (they are
# forwarded, not addressed to the node), so NAT had no connection to map the
# replies back to and UDP/53 from such containers failed. `-m addrtype
# --dst-type LOCAL` keeps the rule on packets for the node itself.
#
# Safe to run on every update: it adds the narrow rule first, then deletes the
# old broad rule until none is left, so there is no moment without a rule for
# queries to the node. Other rules are not touched.
#
# POWERSVX_IPTABLES_RULES_V4 names the saved ruleset of iptables-persistent
# (default /etc/iptables/rules.v4); a broad rule found there is rewritten.
set -uo pipefail

command -v iptables >/dev/null 2>&1 || exit 0

echo "==> Configuring iptables NOTRACK on UDP port 53 (packets for this node only)..."

new_pre=(PREROUTING -p udp -m addrtype --dst-type LOCAL --dport 53 -j NOTRACK)
old_pre=(PREROUTING -p udp --dport 53 -j NOTRACK)
out=(OUTPUT -p udp --sport 53 -j NOTRACK)

iptables -t raw -C "${new_pre[@]}" 2>/dev/null || \
  iptables -t raw -A "${new_pre[@]}" 2>/dev/null || true
iptables -t raw -C "${out[@]}" 2>/dev/null || \
  iptables -t raw -A "${out[@]}" 2>/dev/null || true

# Bounded loop: a duplicate of the old rule is removed too, a failing -D cannot spin.
for _ in $(seq 1 64); do
  iptables -t raw -C "${old_pre[@]}" 2>/dev/null || break
  iptables -t raw -D "${old_pre[@]}" 2>/dev/null || break
done

# A ruleset saved by iptables-persistent would bring the broad rule back at boot.
rules="${POWERSVX_IPTABLES_RULES_V4:-/etc/iptables/rules.v4}"
if [[ -f "$rules" ]] && grep -Eq '^-A PREROUTING -p udp (-m udp )?--dport 53 -j NOTRACK$' "$rules"; then
  echo "==> Migrating the saved ruleset $rules"
  tmp="$(mktemp)" && \
    sed -E 's/^-A PREROUTING -p udp (-m udp )?--dport 53 -j NOTRACK$/-A PREROUTING -p udp -m addrtype --dst-type LOCAL -m udp --dport 53 -j NOTRACK/' "$rules" > "$tmp" && \
    cat "$tmp" > "$rules"
  rm -f "$tmp"
fi
exit 0
