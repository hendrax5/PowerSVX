# PowerSVX + Unbound hybrid

PowerSVX stays the public edge (TPROXY, RPZ, ACL, cache, UI). **Unbound** on loopback does recursive resolution from the root — the expensive path that C Unbound already handles well.

This is **not** forwarding to public resolvers (8.8.8.8 / 1.1.1.1). Traffic control and policy stay on PowerSVX.

## Traffic path

```
Client → nft TPROXY → PowerSVX :53
                         ├ cache hit / RPZ / auth → answer
                         ├ conditional forward zone match → stub upstream
                         └ else → Unbound 127.0.0.1:5353 (recursive)
```

Conditional forward zones are evaluated **first** (longest-suffix). Example: `corp.local` → `10.0.0.1:53` while `google.com` still goes to Unbound.

## Enable on host-network Docker

```bash
docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml up -d --build
```

Unbound starts from [configs/unbound/unbound.conf](../configs/unbound/unbound.conf) on **127.0.0.1:5353** only.

In the UI: **Settings → DNS → Unbound backend** (sets `resolver_mode=forward`, `forwarders=["127.0.0.1:5353"]`, `forward_on_fail=false`). Save.

Or via API:

```bash
curl -sS -X PUT http://127.0.0.1:5380/api/v1/settings \
  -H "Content-Type: application/json" \
  -d '{"resolver_mode":"forward","forwarders":["127.0.0.1:5353"],"forward_on_fail":false}'
```

## Forward per domain (specific sites)

**Settings → DNS → Conditional forward zones**

| Zone | Forwarders | Effect |
|------|------------|--------|
| `corp.local` | `10.1.1.10:53` | Internal AD / private DNS |
| `bank.example` | `192.168.50.2:53` | Stub that zone only |
| *(no match)* | — | Unbound recursive |

Longest suffix wins (`a.corp.local` matches `corp.local`).

## Verify checklist

1. **Unbound up**
   ```bash
   dig @127.0.0.1 -p 5353 example.com A +time=2
   # expect NOERROR / ANSWER
   ```

2. **Default path → Unbound** (with Unbound backend selected, no matching forward zone)
   ```bash
   dig @127.0.0.1 example.com A +time=2
   # PowerSVX answers; metrics path should be forward (via Unbound)
   ```

3. **Conditional zone wins**
   - Add zone `test.invalid` → `127.0.0.1:5353` (or a known stub) in Settings and Save.
   - Query `foo.test.invalid` — should use path `conditional` (not the global Unbound path only by coincidence; check query log / events if available).

4. **Unbound down = clear failure**
   ```bash
   docker stop <unbound-container>
   dig @127.0.0.1 example.com A +time=2
   # expect SERVFAIL / timeout — no silent jump to 8.8.8.8 unless you configured it
   docker start <unbound-container>
   ```

5. **Security**
   - `ss -ulnp | grep 5353` should show `127.0.0.1:5353` only.
   - Public clients must hit PowerSVX `:53`, never Unbound directly.

## Modes compared

| UI preset | Wire `resolver_mode` | Miss path |
|-----------|----------------------|-----------|
| Recursive (Go) | `recursive` | PowerSVX recursive from root |
| Forward | `forward` | Listed forwarders (any) |
| Unbound backend | `forward` | `127.0.0.1:5353` only |

Go recursive remains available for labs without Unbound.

## Related

- A/B gates vs standalone Unbound: [UNBOUND-AB.md](UNBOUND-AB.md)
- Host compose: [deploy/linux/docker-compose.host.yml](../deploy/linux/docker-compose.host.yml)
