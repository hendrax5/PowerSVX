#!/bin/sh
# Warn when this host still has the kernel TPROXY intercept that older PowerSVX
# versions installed from the console (removed in version 2). Nothing is removed
# and the exit status is always 0: the owner decides when to remove it.
#
# What the old code installed (internal/tproxy, deleted in 80255ac):
#   nft table  inet powersvx_tproxy   (prerouting, "tproxy ip to :53")
#   ip rule    fwmark 0x<mark> lookup 100 priority 100   (IPv4 and IPv6, mark 1 by default)
#   ip route   local 0.0.0.0/0 dev lo table 100          (IPv6: local ::/0)
#
# Usage: sh deploy/linux/tproxy-leftover.sh
#   POWERSVX_PRIV  command placed before nft (default "sudo -n" when not root, none as root;
#                  set it empty to run nft as the current user).
# Needs nft and ip on the PATH; a missing tool skips that check.

if [ -z "${POWERSVX_PRIV+x}" ]; then
  POWERSVX_PRIV=""
  if [ "$(id -u 2>/dev/null || echo 0)" != 0 ] && command -v sudo >/dev/null 2>&1; then
    POWERSVX_PRIV="sudo -n"
  fi
fi

found=""

if command -v nft >/dev/null 2>&1; then
  # shellcheck disable=SC2086
  if $POWERSVX_PRIV nft list table inet powersvx_tproxy >/dev/null 2>&1; then
    found="$found
  - nftables table \"inet powersvx_tproxy\""
  fi
fi

if command -v ip >/dev/null 2>&1; then
  for fam in -4 -6; do
    if ip "$fam" rule show 2>/dev/null | grep -Eq 'fwmark [^ ]+ lookup 100( |$)'; then
      found="$found
  - fwmark rule (ip $fam rule: fwmark ... lookup 100)"
    fi
    if ip "$fam" route show table 100 2>/dev/null | grep -Eq '^local .* dev lo'; then
      found="$found
  - local route in table 100 (ip $fam route show table 100)"
    fi
  done
fi

if [ -n "$found" ]; then
  {
    echo "WARNING: this host still has a leftover TPROXY intercept. PowerSVX version 2 has no transparent listener and does not set up or test this path."
    echo "Found:$found"
    echo "Nothing was removed. Remove it with the commands in docs/PRODUCTION.md (\"Leftover TPROXY intercept\")."
  } >&2
fi
exit 0
