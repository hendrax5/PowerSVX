# PowerSVX

Modern DNS server in Go — **Phase 2 Core** (DoT + DoH + DNSSEC validation).

## Features

**Phase 1**
- UDP/TCP DNS listeners (`miekg/dns`)
- Forwarder / recursive resolution
- L1 + L2 BadgerDB cache (pre-encoded wire)
- Optional PostgreSQL zones (loaded into memory)

**Phase 2 (this)**
- **DoT** (DNS-over-TLS, RFC 7858)
- **DoH** (DNS-over-HTTPS HTTP/2, RFC 8484) at `/dns-query`
- **DNSSEC** modes: `off` | `opportunistic` | `validate`

Deferred: DoQ, DoH3, TSIG, zone signing, ACME.

## Quick start (local)

Requires Go 1.26+.

```bash
go mod tidy
go run ./cmd/powersvx --config configs/powersvx.toml
go run ./cmd/dnsquery 127.0.0.1:5353 example.com A
curl http://127.0.0.1:5380/api/v1/status
```

Default UDP/TCP **:5353**. TLS (DoT/DoH) is **off** until certs exist.

### Enable DoT / DoH

```bash
go run ./cmd/gencert ./certs
```

Or use OpenSSL scripts: `configs/gen-dev-certs.ps1` / `configs/gen-dev-certs.sh`.

Then in `configs/powersvx.toml`:

```toml
[server.tls]
enabled = true
cert_file = "./certs/fullchain.pem"
key_file = "./certs/privkey.pem"
```

DoT listens on `dot_port` (default **8853** locally / **853** in Docker).  
DoH listens on `doh_port` (default **8443** locally / **443** in Docker).

```bash
# DoH smoke test (skips TLS verify for self-signed)
go run ./cmd/dohquery https://127.0.0.1:8443/dns-query example.com A

# Or open in browser (convenience query — not RFC wire format):
# https://127.0.0.1:8443/dns-query?name=example.com&type=A

# Plain DNS still works
go run ./cmd/dnsquery 127.0.0.1:5353 example.com A
```

### DNSSEC

```toml
[resolver]
dnssec_mode = "opportunistic"  # or "validate" | "off"
```

- `opportunistic` — sets AD when upstream AD / local RRSIG verifies; never SERVFAIL for DNSSEC  
- `validate` — SERVFAIL on bogus signatures  

## Docker Compose

```bash
# optional: generate host certs if you mount ./certs
./configs/gen-dev-certs.ps1   # or gen-dev-certs.sh

docker compose up -d --build
```

| Host | Container | Service |
|------|-----------|---------|
| 5453 | 53 | DNS UDP/TCP |
| 8853 | 853 | DoT |
| 8443 | 443 | DoH |
| 5380 | 5380 | REST API |
| 5432 | 5432 | Postgres |

Image also embeds a self-signed cert if `./certs` is empty — prefer mounting your own for clients.

## Latency check

```bash
go test ./internal/cache -bench=BenchmarkL1Hit -benchmem
go run ./cmd/bench-hit
```

## License

MIT
