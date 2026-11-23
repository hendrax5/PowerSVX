---
status: accepted
---

# The Auth Backend learns the client address from a PROXY protocol v2 header

Behind dnsdist the Auth Backend used to see the Dataplane's loopback address for every query, so everything the handler decides from the source address (split-horizon views, GeoDNS, the NOTIFY master check, the zone-transfer and update allow lists, the query log) was decided on `127.0.0.1`. dnsdist now sends the real client address to the Auth Backend in a PROXY protocol v2 header, and the Auth Backend believes that header only from a loopback peer. The EDNS client subnet stays as an extra GeoDNS input; it never chooses a view and never passes an allow list.

## What dnsdist 1.9.16 does (measured)

All of this was measured against the pinned `powerdns/dnsdist-19:1.9.16` image and a probe that records the raw bytes the backend receives (`test/unboundloop/probe`, `test/unboundloop/proxy_facts_test.go`; run with `POWERSVX_DOCKER_TESTS=1 go test -run TestFacts ./test/unboundloop/`). The Auth Backend entry was the one `gen-dnsdist-conf.sh` wrote before this change (`useClientSubnet=true`, no PROXY).

| Question | Answer |
|---|---|
| ECS added to forwarded queries | Yes, to UDP and TCP, also when the client sent no EDNS at all: `ECS(family=1 source=/24 scope=/0 addr=172.17.0.0)` for a client at `172.17.0.1`, with an OPT record of size 512 added to a query that had none. The prefix is the default `ecsSourcePrefixV4` (24); the generator does not set it. The IPv6 default (56) was not measured: Docker Desktop gave the lab no IPv6 client. |
| An ECS option the client itself sent | Kept, not replaced: a client that sent `203.0.113.0/24` reached the backend with exactly that option and no option of dnsdist's. The `useClientSubnet` default (`ecsOverride` off) is what produces this. Any client can therefore put any subnet in front of the backend, so ECS cannot be trusted as the identity of the client. |
| AXFR, IXFR, NOTIFY and UPDATE | All decorated the same way, over UDP and TCP (`opcode=NOTIFY`, `opcode=UPDATE` and the AXFR/IXFR questions each arrived with the ECS option). |
| Requests signed with TSIG | dnsdist appended its OPT record after the TSIG record: the backend received `additional=[TSIG,OPT]`, the TSIG was no longer the last record (`IsTsig()` false) and the signed bytes had changed. A TSIG-signed NOTIFY or transfer request cannot be verified behind `useClientSubnet=true`. With PROXY protocol and no `useClientSubnet` the same requests arrive as `additional=[TSIG]`, intact. |
| `useProxyProtocol=true` | A version 2 header in front of every UDP datagram and at the start of every TCP connection: queries, AXFR, NOTIFY and UPDATE. Transport nibble 2 for UDP and 1 for TCP. One backend TCP connection per client connection, one header at its start, several queries after it. |
| dnsdist's health checks | They carry a `LOCAL` header (`proxy=[LOCAL]`, no address block) over UDP, so a backend that requires headers keeps seeing a live Dataplane. A backend that expects headers and gets none would be marked down; the test shows the opposite case (header and `LOCAL` accepted, server stays `up` after 25 s). TCP health checks (`checkTCP=true`) are not enabled by the generator and were not measured. |
| dnsdist's packet cache in front of the Auth Backend | The key is the query bytes, not the PROXY header. With and without PROXY protocol, a second client in the same /24 asking the same name was answered from the entry the first client created: the backend saw one request for two queries from two clients. |

The last two rows decide more than the ticket asked. A TSIG-signed NOTIFY, AXFR or UPDATE never worked through the old configuration, and the Auth Backend packet cache cannot be correct once answers depend on the client (a view or a GeoDNS record set per /32 inside one /24 was already wrong with ECS partitioning, and PROXY protocol removes even that partition).

## Considered Options

- **ECS as the client address.** Rejected. It exists only on requests dnsdist decorates, its /24 prefix is too coarse for views and allow lists that name single addresses, dnsdist keeps an ECS option a client sent (so it can be forged), and the decoration breaks TSIG.
- **PROXY protocol v2 (chosen).** Exact address and port, for UDP and TCP, for every opcode, without touching the DNS message, so TSIG survives.
- **A Go PROXY library.** Rejected: the format is 16 fixed bytes plus an address block and `internal/proxyproto` is about 150 lines with its own tests. No new dependency.

## Decision

**Header handling** (`internal/proxyproto`, `internal/server/proxy_listen.go`):

- A TCP listener wrapper and a UDP `PacketConn` wrapper parse a version 2 header. They accept the `PROXY` command for IPv4 and IPv6 and the `LOCAL` command (the peer address is then the client). Version 1 text headers, other versions, unknown commands, unknown families (including AF_UNIX), a block shorter than its family needs, a truncated header and a header over 1024 bytes are refused.
- The header is read only from a loopback peer. A connection or datagram from any other source is passed on as it came, never parsed for a header, and is refused by the existing non-local rule. A datagram from a stranger that starts with the PROXY signature is dropped without a reply.
- The wrapped connection reports the client as `RemoteAddr()`, so `clientIP` and every consumer of it (views, GeoDNS, NOTIFY check, allow lists, query log) use it unchanged. `proxyproto.TransportPeer` returns the real peer; `isLocalSource` checks that one, never the address a header names.
- Over UDP a reply is written to the datagram's real source, the Dataplane, not to the client address. Only one UDP socket is used in this mode (the SO_REUSEPORT shards of the plain path need the concrete socket); the Auth Backend serves hosted zones only.
- Refused headers and header-less input are counted in `powersvx_proxy_protocol_refused_total`, accepted headers in `powersvx_proxy_protocol_accepted_total`.

**Precedence.** The PROXY address (or the connection's own source when there is no header) is authoritative for views and every allow list. GeoDNS prefers the EDNS client subnet the query carries when the query came from the Dataplane (a recursive resolver acting for an end user is the case it exists for), and uses the client address otherwise. The subnet is ignored for a peer that is not loopback and when `[geodns] ignore_client_subnet = true`. When GeoDNS used a subnet, the answer echoes it with the scope RFC 7871 asks for (the source prefix length) so a resolver caches the answer for that subnet only.

**Enabling it.** `gen-dnsdist-conf.sh` writes `useProxyProtocol=true` on the Auth Backend entry by default (`POWERSVX_AUTH_PROXY_PROTOCOL=1`). In that mode it no longer sets `useClientSubnet` (it would append OPT behind a TSIG record) and writes no packet cache for the `auth` pool. `POWERSVX_AUTH_PROXY_PROTOCOL=0` generates the earlier entry and cache unchanged. The Control Plane's `[server] proxy_protocol` is `"optional"` (default), `"required"` or `"off"`.

**Why those defaults, and the update path.** A node updates in two independent steps: watchtower replaces only the Control Plane image, and `apply-update.sh` regenerates the dnsdist configuration. With `optional` the new Control Plane answers both a header from loopback and a plain query from loopback, so it works with a dnsdist configuration generated before the change and with one generated after it, in either order. Until the dnsdist configuration is regenerated, the Auth Backend still sees `127.0.0.1` for every client, as before. `required` is for a node where both sides are known to be updated; it drops plain queries, so it must not be set while an old dnsdist configuration is in place. Rolling the Control Plane image back while dnsdist already sends headers makes the old binary fail every query to a hosted zone; set `POWERSVX_AUTH_PROXY_PROTOCOL=0`, regenerate, then roll back.

## Trust, and what an unauthenticated peer can and cannot do

- The only trust anchor is the loopback peer. The Auth Backend binds `127.0.0.1` by default (ticket #11) and refuses any other source before processing. Anything that can open a connection from loopback on the node is the Dataplane as far as the Auth Backend can tell; that was already true when the address was loopback.
- A client address named by a header from a non-loopback peer is never used, in any mode; neither is a client subnet from such a peer. A header that names a loopback client does not make its sender trusted.
- ECS from a client can only choose between GeoDNS record sets, as for any authoritative server that supports ECS. It never selects a view and never grants a transfer, update or NOTIFY.
- The black-box test `TestTheAuthBackendJudgesTheRealClientThroughTheDataplane` covers the non-loopback case against the real Control Plane bound to all addresses for the test only.

## Consequences

- The Auth Backend has no dnsdist packet cache in front of it by default. Every query for a hosted zone reaches the Go process. Measure before bringing a cache back; a safe cache needs the client address in its key.
- The IPv6 ECS prefix, TCP health checks, and the behaviour of other dnsdist versions are not covered by the measurements above. A bump of the pinned dnsdist re-runs `TestFacts*`.
- The update path above is a transition. After every node has been regenerated, set `proxy_protocol = "required"` where an attack surface smaller than "any local process can speak plain DNS to the Auth Backend" is wanted.
