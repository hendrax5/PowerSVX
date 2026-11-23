#!/bin/sh
# Generate dnsdist.conf for PowerSVX CDB dataplane (SmartDNS-style).
# Usage: deploy/linux/gen-dnsdist-conf.sh [outfile]
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/configs/dnsdist/dnsdist.conf}"
mkdir -p "$(dirname "$OUT")" "$ROOT/data/blocklist"

MEM_KB=$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 8388608)
NPROC=$(nproc 2>/dev/null || echo 4)
# POWERSVX_HOST_CPUS / POWERSVX_HOST_MEM_MB size the config for a smaller node than
# the machine it is generated on (benchmarks at a fixed size).
case "${POWERSVX_HOST_MEM_MB:-}" in
  '') ;;
  *[!0-9]*) echo "POWERSVX_HOST_MEM_MB must be a whole number of MB" >&2; exit 1 ;;
  *) MEM_KB=$((POWERSVX_HOST_MEM_MB * 1024)) ;;
esac
case "${POWERSVX_HOST_CPUS:-}" in
  '') ;;
  *[!0-9]*|0) echo "POWERSVX_HOST_CPUS must be a positive whole number" >&2; exit 1 ;;
  *) NPROC=$POWERSVX_HOST_CPUS ;;
esac
MEM_MB=$((MEM_KB / 1024))

PACKET_CACHE=500000
if [ "$MEM_MB" -lt 4096 ]; then PACKET_CACHE=200000
elif [ "$MEM_MB" -lt 8192 ]; then PACKET_CACHE=400000
elif [ "$MEM_MB" -ge 16384 ]; then PACKET_CACHE=1000000
fi

UDP_OUT=65535
# One backend socket = one source port = one Unbound so-reuseport thread; spread across threads.
BACKEND_SOCKETS="${POWERSVX_DNSDIST_BACKEND_SOCKETS:-$((NPROC * 2))}"
if [ "$BACKEND_SOCKETS" -lt 8 ]; then BACKEND_SOCKETS=8; fi
if [ "$BACKEND_SOCKETS" -gt 64 ]; then BACKEND_SOCKETS=64; fi

# Tuning knobs (ticket #18). Each is off by default, which keeps today's configuration.
# POWERSVX_DNSDIST_UDP_LISTENERS: UDP listeners per address. 1 (default) = one thread receives
# every UDP query; N > 1 = N listeners with reusePort=true, one receive thread each; auto = CPUs.
UDP_LISTENERS="${POWERSVX_DNSDIST_UDP_LISTENERS:-1}"
case "$UDP_LISTENERS" in
  auto) UDP_LISTENERS=$NPROC; if [ "$UDP_LISTENERS" -gt 64 ]; then UDP_LISTENERS=64; fi ;;
  *[!0-9]*|0|0?*) echo "POWERSVX_DNSDIST_UDP_LISTENERS must be auto or a whole number from 1 to 64" >&2; exit 1 ;;
  *) if [ "$UDP_LISTENERS" -gt 64 ]; then echo "POWERSVX_DNSDIST_UDP_LISTENERS must be auto or a whole number from 1 to 64" >&2; exit 1; fi ;;
esac
# POWERSVX_DNSDIST_CACHE_SHARDS: shards of the main packet cache. Unset (default) = dnsdist's
# own default of one; auto = CPUs; or a whole number from 1 to 64.
CACHE_SHARDS="${POWERSVX_DNSDIST_CACHE_SHARDS:-}"
case "$CACHE_SHARDS" in
  '') ;;
  auto) CACHE_SHARDS=$NPROC; if [ "$CACHE_SHARDS" -gt 64 ]; then CACHE_SHARDS=64; fi ;;
  *[!0-9]*|0|0?*) echo "POWERSVX_DNSDIST_CACHE_SHARDS must be auto or a whole number from 1 to 64" >&2; exit 1 ;;
  *) if [ "$CACHE_SHARDS" -gt 64 ]; then echo "POWERSVX_DNSDIST_CACHE_SHARDS must be auto or a whole number from 1 to 64" >&2; exit 1; fi ;;
esac
CACHE_OPTS=""
if [ -n "$CACHE_SHARDS" ]; then CACHE_OPTS=", numberOfShards=${CACHE_SHARDS}"; fi

TCP_THREADS=$((NPROC * 2))
if [ "$TCP_THREADS" -lt 4 ]; then TCP_THREADS=4; fi
if [ "$TCP_THREADS" -gt 32 ]; then TCP_THREADS=32; fi

SPOOF_V4="${POWERSVX_SPOOF_IPV4:-139.255.196.196}"
SPOOF_V6="${POWERSVX_SPOOF_IPV6:-::}"
DNSDIST_KEY="${POWERSVX_DNSDIST_KEY:-powersvx-dnsdist-console}"
WEB_PASS="${POWERSVX_DNSDIST_WEB_PASSWORD:-powersvx}"
API_KEY="${POWERSVX_DNSDIST_API_KEY:-powersvx-api}"
RECURSIVE_PORT="${POWERSVX_UNBOUND_BACKEND_PORT:-5353}"
AUTH_PORT="${POWERSVX_AUTH_BACKEND_PORT:-5354}"
# 1 (default): dnsdist sends a PROXY protocol v2 header with the real client address to the Auth Backend
# (docs/adr/0003). Then dnsdist adds no ECS option (it would sit behind a TSIG record and break the
# signature) and the Auth Backend pool has no packet cache (the cache key cannot contain the PROXY address,
# and the answer depends on the client). 0: the earlier behaviour, ECS from dnsdist and a packet cache.
AUTH_PROXY="${POWERSVX_AUTH_PROXY_PROTOCOL:-1}"
AUTH_OPTS=" useClientSubnet=true,"
if [ "$AUTH_PROXY" = "1" ]; then AUTH_OPTS=" useProxyProtocol=true,"; fi
CDB_REFRESH="${POWERSVX_CDB_REFRESH_SEC:-30}"
PTR_QPS="${POWERSVX_PTR_QPS_PER_IP:-50}"

# auto: listen on [::]:53 only when the host has a global IPv6 address.
LISTEN_V6="${POWERSVX_DNSDIST_IPV6:-auto}"
if [ "$LISTEN_V6" = "auto" ]; then
  if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then LISTEN_V6=1; else LISTEN_V6=0; fi
fi

# Ensure valid empty CDBs (tinycdb: 256×(pos=2048,nslots=0)) so dnsdist starts before first sync.
for CDB_NAME in domains.cdb whitelist.cdb custom_blacklist.cdb authzones.cdb; do
  if [ ! -f "$ROOT/data/blocklist/$CDB_NAME" ]; then
    if command -v python3 >/dev/null 2>&1; then
      python3 -c "
import struct
path = r'''$ROOT/data/blocklist/$CDB_NAME'''
open(path, 'wb').write(b''.join(struct.pack('<II', 2048, 0) for _ in range(256)))
"
    else
      dd if=/dev/zero of="$ROOT/data/blocklist/$CDB_NAME" bs=2048 count=1 2>/dev/null || true
    fi
  fi
done

if [ ! -f "$ROOT/data/blocklist/bans.txt" ]; then
  echo "# PowerSVX manual IP bans" >"$ROOT/data/blocklist/bans.txt"
fi
if [ ! -f "$ROOT/data/blocklist/dynblock.lua" ]; then
  cat >"$ROOT/data/blocklist/dynblock.lua" <<'D'
-- Default PowerSVX dynblock group
dbrg = dynBlockRulesGroup()
D
fi

WL="$ROOT/data/blocklist/banks.whitelist"
if [ ! -f "$WL" ]; then
  cat >"$WL" <<'W'
bca.co.id
klikbca.com
bankmandiri.co.id
mandiri.co.id
livin.co.id
bri.co.id
bni.co.id
btn.co.id
bsi.co.id
W
fi

TMP="${OUT}.tmp.$$"
{
  echo "-- AUTO-GENERATED by deploy/linux/gen-dnsdist-conf.sh"
  echo "-- host Mem=${MEM_MB}MB packetCache=${PACKET_CACHE} authPort=${AUTH_PORT} recPort=${RECURSIVE_PORT}"
  echo ""
  echo "setACL({\"0.0.0.0/0\", \"::/0\"})"
  if [ "$UDP_LISTENERS" -gt 1 ]; then
    i=0
    while [ "$i" -lt "$UDP_LISTENERS" ]; do
      echo "addLocal(\"0.0.0.0:53\", {reusePort=true})"
      i=$((i + 1))
    done
  else
    echo "addLocal(\"0.0.0.0:53\")"
  fi
  if [ "$LISTEN_V6" = "1" ]; then
    if [ "$UDP_LISTENERS" -gt 1 ]; then
      i=0
      while [ "$i" -lt "$UDP_LISTENERS" ]; do
        echo "addLocal(\"[::]:53\", {reusePort=true})"
        i=$((i + 1))
      done
    else
      echo "addLocal(\"[::]:53\")"
    fi
  else
    echo "-- addLocal(\"[::]:53\") disabled (POWERSVX_DNSDIST_IPV6=0 or no global IPv6)"
  fi
  echo ""
  cat <<'TLSLUA'
-- Auto-enable DoT (:853), DoH (:443) and DoQ (UDP :784) when TLS certificates are mounted at /etc/dnsdist/certs/
local function fileExists(p)
  local f = io.open(p, "r")
  if f ~= nil then f:close(); return true end
  return false
end
local tlsCert = "/etc/dnsdist/certs/fullchain.pem"
local tlsKey = "/etc/dnsdist/certs/privkey.pem"
if fileExists(tlsCert) and fileExists(tlsKey) then
  addTLSLocal("0.0.0.0:853", tlsCert, tlsKey)
  addDOHLocal("0.0.0.0:443", tlsCert, tlsKey, "/dns-query")
  addDOQLocal("0.0.0.0:784", tlsCert, tlsKey)
  infolog("powersvx DoT (:853), DoH (:443) and DoQ (:784) enabled with /etc/dnsdist/certs/")
end
TLSLUA
  echo ""
  # PowerSVX writes allow_query/deny_query to blocklist/acl.txt, manual bans to bans.txt, and RRL to dynblock.lua.
  cat <<'LUA'
local aclPath = "/etc/dnsdist/blocklist/acl.txt"
local aclLast = nil
local function reloadACL()
  local f = io.open(aclPath, "r")
  if f == nil then return end
  local body = f:read("*a")
  f:close()
  if body == nil or body == aclLast then return end
  aclLast = body
  local masks = {}
  for line in body:gmatch("[^\r\n]+") do
    line = line:gsub("^%s+", ""):gsub("%s+$", "")
    if line ~= "" and line:sub(1, 1) ~= "#" then table.insert(masks, line) end
  end
  if #masks == 0 then return end
  local ok, err = pcall(setACL, masks)
  if ok then
    infolog("powersvx acl loaded: " .. #masks .. " masks")
  else
    errlog("powersvx acl rejected: " .. tostring(err))
  end
end

local dynPath = "/etc/dnsdist/blocklist/dynblock.lua"
local dynLast = nil
local function reloadDynBlock()
  local f = io.open(dynPath, "r")
  if f == nil then return end
  local body = f:read("*a")
  f:close()
  if body == nil or body == dynLast then return end
  dynLast = body
  local ok, err = pcall(dofile, dynPath)
  if ok then
    infolog("powersvx dynblock rules reloaded")
  else
    errlog("powersvx dynblock reload error: " .. tostring(err))
  end
end

local bansPath = "/etc/dnsdist/blocklist/bans.txt"
local bansLast = nil
local function reloadBans()
  local f = io.open(bansPath, "r")
  if f == nil then return end
  local body = f:read("*a")
  f:close()
  if body == nil or body == bansLast then return end
  bansLast = body
  local nmg = newNMG()
  local cnt = 0
  for line in body:gmatch("[^\r\n]+") do
    line = line:gsub("^%s+", ""):gsub("%s+$", "")
    if line ~= "" and line:sub(1, 1) ~= "#" then
      nmg:addMask(line)
      cnt = cnt + 1
    end
  end
  if cnt > 0 then
    pcall(addDynBlocks, nmg, "PowerSVX manual ban", 86400)
    infolog("powersvx manual bans applied: " .. cnt)
  end
end

reloadACL()
reloadDynBlock()
reloadBans()
function maintenance()
  reloadACL()
  reloadDynBlock()
  reloadBans()
  if dbrg ~= nil then
    pcall(function() dbrg:apply() end)
  end
end
LUA
  echo ""
  echo "-- controlSocket disabled; use webserver on 127.0.0.1:8083"
  echo ""
  echo "setRingBuffersSize(1000000)"
  echo "setMaxUDPOutstanding(${UDP_OUT})"
  echo "setMaxTCPClientThreads(${TCP_THREADS})"
  echo "setMaxTCPQueuedConnections(1000)"
  echo "setMaxTCPConnectionsPerClient(20)"
  echo ""
  # Recursive backend pool (Unbound) and Authoritative backend pool (PowerSVX Go :5354)
  echo "newServer({address=\"127.0.0.1:${RECURSIVE_PORT}\", name=\"unbound\", sockets=${BACKEND_SOCKETS}, checkInterval=2, maxCheckFailures=5, checkTimeout=2000, rise=2})"
  echo "newServer({address=\"127.0.0.1:${AUTH_PORT}\", name=\"powersvx-auth\", pool=\"auth\",${AUTH_OPTS} checkInterval=5, maxCheckFailures=3, checkTimeout=2000, rise=2})"
  echo "setServerPolicy(leastOutstanding)"
  echo ""
  echo "pc = newPacketCache(${PACKET_CACHE},{maxTTL=86400, minTTL=60, maxNegativeTTL=300${CACHE_OPTS}})"
  echo "getPool(\"\"):setCache(pc)"
  if [ "$AUTH_PROXY" != "1" ]; then
    echo "pcAuth = newPacketCache(50000,{maxTTL=300, minTTL=0, maxNegativeTTL=60})"
    echo "getPool(\"auth\"):setCache(pcAuth)"
  fi
  echo ""
  echo "local authzonesKVS = newCDBKVStore(\"/etc/dnsdist/blocklist/authzones.cdb\",${CDB_REFRESH})"
  echo "local whitelistKVS = newCDBKVStore(\"/etc/dnsdist/blocklist/whitelist.cdb\",${CDB_REFRESH})"
  echo "local customBlackKVS = newCDBKVStore(\"/etc/dnsdist/blocklist/custom_blacklist.cdb\",${CDB_REFRESH})"
  echo "local blocklistKVS = newCDBKVStore(\"/etc/dnsdist/blocklist/domains.cdb\",${CDB_REFRESH})"
  echo "local suffixLookupKey = KeyValueLookupKeySuffix(2,false)"
  echo ""
  if [ -f "$ROOT/data/blocklist/banks.lua" ]; then
    echo "dofile(\"/etc/dnsdist/blocklist/banks.lua\")"
  else
    echo "whitelistSMN = newSuffixMatchNode()"
    while IFS= read -r d || [ -n "$d" ]; do
      d=$(echo "$d" | tr -d '\r' | tr '[:upper:]' '[:lower:]')
      case "$d" in ''|\#*) continue ;; esac
      d=${d%.}
      echo "whitelistSMN:add(newDNSName(\"${d}.\"))"
    done <"$WL"
  fi
  echo ""
  echo "-- 0. Route inbound DNS NOTIFY directly to PowerSVX Auth/Slave handler :${AUTH_PORT}"
  echo "addAction(OpcodeRule(DNSOpcode.Notify), PoolAction(\"auth\"))"
  echo ""
  echo "-- 1. Route hosted authoritative zones (+ ACME challenges) directly to PowerSVX Auth :${AUTH_PORT}"
  echo "addAction(KeyValueStoreLookupRule(authzonesKVS,suffixLookupKey), PoolAction(\"auth\"))"
  echo ""
  echo "-- 2. Whitelist (official banks + custom UI whitelist) bypasses all filters"
  echo "addAction(KeyValueStoreLookupRule(whitelistKVS,suffixLookupKey), PoolAction(\"\"))"
  echo "addAction(SuffixMatchNodeRule(whitelistSMN), PoolAction(\"\"))"
  echo ""
  echo "-- 3. Custom operator/admin blacklist"
  echo "addAction(AndRule({KeyValueStoreLookupRule(customBlackKVS,suffixLookupKey), QTypeRule(DNSQType.AAAA)}), SpoofAction(\"${SPOOF_V6}\"))"
  echo "addAction(AndRule({KeyValueStoreLookupRule(customBlackKVS,suffixLookupKey), QTypeRule(DNSQType.A)}), SpoofAction(\"${SPOOF_V4}\"))"
  echo "addAction(KeyValueStoreLookupRule(customBlackKVS,suffixLookupKey), RCodeAction(DNSRCode.NOERROR))"
  echo ""
  # CPE PTR storms recurse to dead reverse NS; cap per client instead of blocking PTR.
  echo "addAction(AndRule({QTypeRule(DNSQType.PTR), MaxQPSIPRule(${PTR_QPS})}), RCodeAction(DNSRCode.REFUSED))"
  echo ""
  echo "-- 4. Main RPZ/Kominfo blocklist CDB"
  echo "addAction(AndRule({KeyValueStoreLookupRule(blocklistKVS,suffixLookupKey), QTypeRule(DNSQType.AAAA)}), SpoofAction(\"${SPOOF_V6}\"))"
  echo "addAction(AndRule({KeyValueStoreLookupRule(blocklistKVS,suffixLookupKey), QTypeRule(DNSQType.A)}), SpoofAction(\"${SPOOF_V4}\"))"
  echo "-- Non-A/AAAA queries (e.g. HTTPS type 65, MX, TXT) on blocked domains return NODATA (NOERROR) to prevent upstream leak & trigger browser A/AAAA fallback"
  echo "addAction(KeyValueStoreLookupRule(blocklistKVS,suffixLookupKey), RCodeAction(DNSRCode.NOERROR))"
  echo ""
  echo "addAction(AllRule(), PoolAction(\"\"))"
  echo "setSecurityPollSuffix(\"\")"
  echo ""
  echo "webserver(\"127.0.0.1:8083\")"
  echo "setWebserverConfig({password=\"${WEB_PASS}\", apiKey=\"${API_KEY}\", acl=\"127.0.0.1\"})"
} >"$TMP"

mv -f "$TMP" "$OUT"
echo "dnsdist-conf: wrote $OUT (cache=${PACKET_CACHE} spoof=${SPOOF_V4} rec=:${RECURSIVE_PORT} auth=:${AUTH_PORT} sockets=${BACKEND_SOCKETS} ipv6=${LISTEN_V6} udp-listeners=${UDP_LISTENERS} cache-shards=${CACHE_SHARDS:-default})" >&2
