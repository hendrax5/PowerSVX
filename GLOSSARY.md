# PowerSVX

An ISP DNS stack: a recursive resolver with regulatory filtering, authoritative zones, and an operations console, deployed per node across a fleet.

## Language

### Planes

**Dataplane**:
The component that answers client DNS queries on the public port. There is exactly one: dnsdist in front of Unbound.
_Avoid_: Edge, Go edge, engine, DNS server

**Control Plane**:
The PowerSVX process. It manages the Dataplane and serves the console and API, and never answers recursive client queries.
_Avoid_: Backend, PowerSVX server, the Go server

**Auth Backend**:
The part of the Control Plane that answers queries for Authoritative Zones, reached only through the Dataplane.
_Avoid_: Auth pool, authoritative server

### Filtering

**Filter**:
The set of domain names the Dataplane must not resolve normally, together with the action taken for each.
_Avoid_: Blocklist, RPZ (as a synonym), blacklist

**Filter Feed**:
An upstream source of Filter names, pulled by zone transfer or file download.
_Avoid_: RPZ feed, policy source

**Filter Seed**:
A prebuilt snapshot of a Filter Feed used to bring a new node into service before its first full transfer completes.
_Avoid_: Bootstrap blocklist

### Zones

**Authoritative Zone**:
A zone whose records this node owns and signs.
_Avoid_: Domain, primary zone

**Secondary Zone**:
A read-only copy of a zone owned elsewhere, kept current by zone transfer.
_Avoid_: Slave zone

### Deployment

**Core Profile**:
The minimum set of services a node needs to answer queries and be managed: Dataplane and Control Plane.
_Avoid_: Minimal stack, lite mode

**Observability Profile**:
Optional services that store and chart history; a node keeps answering queries without them.
_Avoid_: Monitoring stack, analytics

### Measurement

**Reference Load**:
The query mix every performance claim is measured against: ISP recursive traffic with the Filter active and roughly nine in ten queries answerable from cache.
_Avoid_: Benchmark traffic, test load

**Baseline**:
A measurement of Technitium and of PowerSVX under the Reference Load on the same hardware, taken before any target is set.
_Avoid_: Benchmark result

### Observation

**Query Log**:
A sample of the queries the Dataplane answers, sent by dnsdist to the Control Plane over a local socket. Each entry names the Filter action actually taken. Off by default; the console's live query stream shows it, and history is stored only in the Observability Profile.
_Avoid_: Query sampler, query analytics
