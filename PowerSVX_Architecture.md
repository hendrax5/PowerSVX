# PowerSVX — Modern DNS Server

> **Performa Unbound + Fleksibilitas CoreDNS + UI Modern Technitium + API PowerSVX — dalam satu binary Go.**

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Feature Specification](#4-feature-specification)
5. [Performance Targets](#5-performance-targets)
6. [RPZ Architecture (20M Rules)](#6-rpz-architecture-20m-rules)
7. [Cache Hierarchy](#7-cache-hierarchy)
8. [Database Schema](#8-database-schema)
9. [Configuration (TOML)](#9-configuration-toml)
10. [Docker Compose Deployment](#10-docker-compose-deployment)
11. [UI/UX Design](#11-uiux-design)
12. [API Specification](#12-api-specification)
13. [WebSocket Events](#13-websocket-events)
14. [Plugin System](#14-plugin-system)
15. [HA Clustering](#15-ha-clustering)
16. [Observability](#16-observability)
17. [Security Considerations](#17-security-considerations)
18. [Deployment Guide](#18-deployment-guide)
19. [Monitoring & Alerting](#19-monitoring--alerting)
20. [Roadmap](#20-roadmap)

---

## 1. Overview

PowerSVX is a next-generation DNS server built in Go, designed to fill the gap in the open-source DNS ecosystem. It combines the performance of Unbound, the plugin flexibility of CoreDNS, the modern UI of Technitium, and the API power of PowerSVX — all in a single deployable binary.

### Key Differentiators

| Aspect | Existing Solutions | PowerSVX (This) |
|--------|-------------------|-----------------|
| Language | C# (Technitium), C++ (Unbound/PowerSVX) | **Go** |
| UI | Technitium ✅, others ❌ | **React Modern** |
| DoQ (DNS-over-QUIC) | Technitium ✅, others partial | **Native quic-go** |
| RPZ Scale | ~100K rules typical | **20M rules, <1ms lookup** |
| Plugin Hot-Reload | CoreDNS ❌ (recompile) | **Lua + WASM runtime** |
| Clustering | Complex external tools | **Built-in Raft** |
| Cache Latency | ~5-10ms | **<5ms p99** |

### Deployment Modes

- **Standalone**: Single node, recursive + authoritative
- **Cluster**: 3+ nodes with Raft consensus
- **Cache-only**: Forwarding resolver with massive RPZ

---

## 2. Architecture

### 2.1 High-Level Data Flow

```
Client Request
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  UDP:53  TCP:53  DoT:853  DoH:443  DoQ:784              │
│     │       │       │        │         │                │
│     ▼       ▼       ▼        ▼         ▼                │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌──────┐ ┌─────┐            │
│  │ UDP │ │ TCP │ │ DoT │ │ DoH/3│ │ DoQ │            │
│  └─────┘ └─────┘ └─────┘ └──────┘ └─────┘            │
│     │       │       │        │         │                │
│     └───────┴───────┴────────┴─────────┘                │
│                    │                                    │
│                    ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │  UNIFIED REQUEST PIPELINE                        │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐ │   │
│  │  │  Rate   │ │  Lua/   │ │   RPZ   │ │ Split  │ │   │
│  │  │ Limiter │ │  WASM   │ │ Check   │ │Horizon │ │   │
│  │  └─────────┘ │  Hook   │ └─────────┘ └────────┘ │   │
│  │              │ (pre)   │                      │   │
│  │              └─────────┘                      │   │
│  └─────────────────────────────────────────────────┘   │
│                    │                                    │
│                    ▼                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │  AUTHORITATIVE vs RECURSIVE DECISION              │   │
│  │                                                   │   │
│  │  ┌─────────────┐      ┌─────────────────────┐   │   │
│  │  │ Authoritative│      │ Recursive Resolver  │   │   │
│  │  │ • Zone lookup│      │ • Cache check       │   │   │
│  │  │ • Wildcard   │      │ • ECS extraction    │   │   │
│  │  │ • GeoDNS     │      │ • Forward/Iterate   │   │   │
│  │  │ • DNSSEC sign│      │ • DNSSEC validate   │   │   │
│  │  └─────────────┘      └─────────────────────┘   │   │
│  │         │                      │                │   │
│  │         └──────────┬───────────┘                │   │
│  │                    │                             │   │
│  │                    ▼                             │   │
│  │  ┌─────────────────────────────────────────────┐ │   │
│  │  │  RESPONSE POST-PROCESSING                    │ │   │
│  │  │  Cache → Lua/WASM → GeoIP → Query Log       │ │   │
│  │  └─────────────────────────────────────────────┘ │   │
│  │                    │                             │   │
│  │                    ▼                             │   │
│  │  ┌─────────────────────────────────────────────┐ │   │
│  │  │  RESPONSE BACK TO CLIENT                     │ │   │
│  │  └─────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  BACKGROUND SERVICES                                     │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐           │
│  │  Raft  │ │  Zone  │ │ Threat │ │  ACME  │           │
│  │Consensus│ │Transfer│ │ Intel  │ │ DNS-01 │           │
│  └────────┘ └────────┘ └────────┘ └────────┘           │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐           │
│  │Prometheus│ │OpenTel.│ │   AI   │ │ Config │           │
│  │Exporter│ │ Tracer │ │Analyzer│ │Watcher │           │
│  └────────┘ └────────┘ └────────┘ └────────┘           │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Project Structure

```
PowerSVX/
├── cmd/PowerSVX/              # Entry point
├── internal/
│   ├── server/                # UDP/TCP/DoT/DoH/DoQ listeners
│   ├── resolver/              # Recursive resolver engine
│   ├── authoritative/         # Zone management & DNSSEC signing
│   ├── cache/                 # Multi-tier cache (L1/L2/L3)
│   ├── rpz/                   # Response Policy Zone (20M rules)
│   ├── geo/                   # GeoDNS & ECS handling
│   ├── api/                   # REST & gRPC APIs
│   ├── web/                   # React SPA static files
│   ├── cluster/               # Raft-based HA clustering
│   ├── scripting/             # Lua & WASM plugin engine
│   ├── metrics/               # Prometheus & OpenTelemetry
│   ├── ai/                    # Query analysis (anomaly detection)
│   ├── config/                # Configuration management
│   ├── database/              # PostgreSQL repository
│   └── acme/                  # ACME DNS-01 challenge
├── pkg/                       # Shared packages
├── web/                       # React source code
├── configs/                   # Docker, SQL, Grafana, Prometheus
├── plugins/                   # Example Lua/WASM plugins
├── docs/                      # Documentation
├── Dockerfile
├── docker-compose.yml
├── go.mod
└── README.md
```

---

## 3. Technology Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| **DNS Engine** | `miekg/dns` | v1.1.62 | Core DNS library |
| **QUIC/DoQ** | `quic-go` | v0.48 | DNS-over-QUIC (RFC 9250) |
| **HTTP/3** | `quic-go/http3` | v0.48 | DoH3 support |
| **Cache L1** | `sync.Map` | stdlib | In-process hot cache |
| **Cache L2** | `dgraph-io/badger/v4` | v4.3 | Local persistent cache |
| **Cache L3** | `redis/go-redis/v9` | v9.5 | Distributed cache |
| **Database** | `lib/pq` / `pgx/v5` | v5.6 | PostgreSQL driver |
| **Raft** | `hashicorp/raft` | v1.7 | Cluster consensus |
| **Lua** | `yuin/gopher-lua` | v1.1 | Lua scripting engine |
| **WASM** | `tetratelabs/wazero` | v1.7 | WebAssembly runtime |
| **Metrics** | `prometheus/client_golang` | v1.20 | Prometheus metrics |
| **Tracing** | `go.opentelemetry.io/otel` | v1.28 | OpenTelemetry SDK |
| **TLS** | `golang.org/x/crypto` | latest | TLS 1.3, ACME |
| **GeoIP** | `oschwald/geoip2-golang` | v1.9 | MaxMind GeoIP2 |
| **Frontend** | React + Vite | v18.3 | Web UI |
| **Charts** | Recharts | v2.12 | Data visualization |
| **Styling** | Tailwind CSS | v3.4 | Utility-first CSS |

---

## 4. Feature Specification

### 4.1 Core DNS Features

| Feature | Status | Detail |
|---------|--------|--------|
| Recursive Resolver | Required | Root hints, iterative resolution, forwarder mode |
| Authoritative Zone | Required | Master/slave, AXFR/IXFR, NOTIFY, TSIG |
| DNSSEC | Required | Signing (ZSK/KSK), validation, NSEC/NSEC3, ECDSAP256SHA256 |
| Wildcard Records | Required | `*.example.com` with closest encloser logic |
| Split Horizon | Important | Per-source-network views (internal/external) |
| GeoDNS | Important | Continent/country/city routing via MaxMind GeoIP2 |
| ECS (EDNS Client Subnet) | Important | RFC 7871, forward to upstream, cache isolation |

### 4.2 Encrypted DNS

| Protocol | Port | RFC | Status |
|----------|------|-----|--------|
| DoT (DNS-over-TLS) | 853 | RFC 7858 | Required |
| DoH (DNS-over-HTTPS) | 443 | RFC 8484 | Required |
| DoH3 (DNS-over-HTTP/3) | 443 | RFC 8484 + HTTP/3 | Required |
| DoQ (DNS-over-QUIC) | 784 | RFC 9250 | Important |

### 4.3 Security Features

| Feature | Status | Detail |
|---------|--------|--------|
| RPZ (Response Policy Zone) | Required | 20M rules, <1ms lookup, wildcard support |
| Blocklist | Required | Hosts file, domain list, auto-update feeds |
| Rate Limiter | Important | Token bucket per /32, per subnet, adaptive |
| Threat Intelligence | Nice | Auto-update from URLhaus, StevenBlack, etc. |
| AI Query Analysis | Nice | Anomaly detection, DDoS pattern recognition |

### 4.4 Management & Operations

| Feature | Status | Detail |
|---------|--------|--------|
| REST API | Required | Full CRUD for zones, records, settings |
| gRPC API | Nice | High-performance internal API |
| Query Log | Important | PostgreSQL, partitioned, 30-day retention |
| Grafana Dashboard | Important | Pre-built dashboards for all metrics |
| Prometheus Metrics | Important | Standard + custom metrics, :9100 |
| OpenTelemetry | Nice | Distributed tracing, 1% sampling |
| HA Cluster | Important | Raft consensus, 3+ nodes, anycast |
| Plugin System | Important | Lua + WASM hooks, hot-reload |
| ACME DNS-01 | Nice | Let's Encrypt integration |

---

## 5. Performance Targets

| Metric | Target | Benchmark Tool | Notes |
|--------|--------|----------------|-------|
| **QPS (UDP)** | 500,000+ | `dnsperf` / `flamethrower` | 10 clients, 1000 concurrent |
| **QPS (DoH)** | 100,000+ | `h2load` / custom | HTTP/2 multiplexing |
| **Cache Latency p99** | < 5ms | Custom benchmark | Includes RPZ lookup |
| **RPZ Lookup (20M)** | < 1ms | Custom benchmark | Radix tree + Bloom filter |
| **Memory (1M cache)** | < 200MB | `pprof` | Pre-encoded responses |
| **DNSSEC Signing** | < 1ms/zone | Custom benchmark | ECDSA P-256 |
| **Cluster Failover** | < 1s | Custom | Leader election |
| **Plugin Overhead** | < 0.1ms | Custom benchmark | Lua/WASM execution |

### Latency Budget (< 5ms p99)

```
Component                    Budget
─────────────────────────────────────
Packet parse                 0.05 ms
Rate limit check             0.05 ms
RPZ lookup (radix tree)      0.05 ms  (99% hit)
  └─ Fallback BadgerDB       0.30 ms  (1% miss)
Cache lookup (L1 sync.Map)    0.05 ms  (80% hit)
  └─ Fallback BadgerDB         0.20 ms  (15% hit)
  └─ Fallback Redis            0.50 ms  (5% hit)
Resolution (cache hit)         1.00 ms
  └─ Upstream query           20.00 ms  (async, acceptable)
DNSSEC validation              0.50 ms
Response build                 0.10 ms
Plugin hooks (Lua/WASM)        0.50 ms  (max budget)
Network write                  0.05 ms
─────────────────────────────────────
Total (cache hit)             ~2.5 ms  [PASS]
Total (cache miss)           ~22.5 ms  (async upstream)
```

---

## 6. RPZ Architecture (20M Rules)

### 6.1 Problem Analysis

Traditional approaches fail at 20M scale:

| Approach | Latency | Memory | Wildcard | Verdict |
|----------|---------|--------|----------|---------|
| PostgreSQL B-Tree | 2-5ms | ~2GB index | No | Too slow |
| Redis Hash | ~0.5ms | 2-4GB | No | No wildcard, network RTT |
| Linear scan | O(n) | Minimal | Yes | Impossible |
| **Tiered (Radix + BadgerDB)** | **<1ms** | **~100MB** | **Yes** | **Solution** |

### 6.2 Tiered RPZ Architecture

```
RPZ LOOKUP PIPELINE (< 2ms target)
───────────────────────────────────

TIER 1: IN-MEMORY RADIX TREE (Hot Cache)
───────────────────────────────────────────
• Structure: Compressed trie (domain labels reversed)
• Example: "com.google.tracker" -> [block]
• Capacity: 500K most-recently-hit rules
• Latency: ~50-100 nanoseconds
• Memory: ~50MB (500K entries x 100 bytes)

    root
     |
  ┌──┴──┬─────┬─────┐
  ▼     ▼     ▼     ▼
 com   org   net   io
  |
  ├─────┐
  ▼     ▼
google facebook
  |
  ┌──┴──┐
  ▼     ▼
tracker ads
[BLOCK] [BLOCK]

Wildcard: *.google.com -> node "google" marked wildcard
Exact: tracker.google.com -> leaf node

    |
    | MISS (not in hot cache)
    ▼

TIER 2: LOCAL BADGERDB LSM-TREE (Full Dataset)
───────────────────────────────────────────────
• Structure: Key = reversed domain, Value = action+metadata
• Example: Key="moc.elgoog.rekcart", Value="nxdomain|ads"
• Bloom filter: Check membership O(1) before disk lookup
• Latency: ~0.2-0.5ms (NVMe SSD)
• Size: ~4GB (20M x 200 bytes, compressed)
• Update: Background merge, non-blocking

Bloom Filter (in-memory, 20M entries):
• False positive rate: 0.1%
• Memory: ~30MB
• "Is this domain blocked?" -> 99.9% accurate in O(1)

    |
    | MISS (not in blocklist at all)
    ▼

TIER 3: NEGATIVE CACHE (Confirmed Clean Domains)
───────────────────────────────────────────────
• Cuckoo filter: "Domain already checked and CLEAN"
• Avoid repeat lookup to BadgerDB for popular domains
• Memory: ~20MB (10M entries)
• TTL: 5 minutes (refresh periodically)

UPDATE MECHANISM (Background, non-blocking)
─────────────────────────────────────────
• Download feeds -> Parse -> Build new radix tree + Badger batch
• Atomic swap: old tree <-> new tree (RCU pattern)
• Zero downtime update, < 1ms pause

Total time: ~30-60 seconds (background)
Impact to queries: ZERO
```

### 6.3 Memory & Storage Calculation

| Component | Count | Size/Entry | Total |
|-----------|-------|------------|-------|
| Radix Tree (hot) | 500K | 100 bytes | **50 MB** |
| Bloom Filter | 20M | 1.5 bits | **30 MB** |
| Cuckoo Filter (negative) | 10M | 2 bytes | **20 MB** |
| BadgerDB (full) | 20M | 200 bytes (compressed) | **~4 GB disk** |
| **Total RAM** | | | **~100 MB** |
| **Total Disk** | | | **~4 GB** |

### 6.4 Update Flow (Background)

```
1. DOWNLOAD
   - curl https://stevenblack.github.io/hosts/hosts
   - curl https://urlhaus.abuse.ch/downloads/hostfile/
   - ... (configurable feeds)

2. PARSE & DEDUPLICATE
   - Parse hosts format -> domain list
   - Remove duplicates (map[string]struct{})
   - Validate domains (IDNA, punycode)
   - Output: 20M unique domains

3. BUILD NEW RADIX TREE (Background goroutine)
   - Allocate new tree structure
   - Insert all 20M domains (reversed labels)
   - Mark wildcard nodes (*.example.com)
   - Attach action metadata (nxdomain, redirect_ip, etc)

4. BUILD NEW BADGERDB BATCH
   - Open new BadgerDB instance (versioned)
   - Batch insert 20M key-value pairs
   - Build Bloom filter (30MB in-memory)
   - Compact LSM tree

5. ATOMIC SWAP (RCU - Read-Copy-Update)
   - Lock-free pointer swap: old_tree -> new_tree
   - Old tree marked for GC (delayed free)
   - BadgerDB: symlink swap to new version
   - Cuckoo filter cleared (will rebuild on next queries)

6. ZERO DOWNTIME
   - Query pipeline never stops
   - Swap takes < 1 microsecond
   - Old resources freed after all readers complete
```

---

## 7. Cache Hierarchy

### 7.1 Three-Tier Cache

```
CACHE HIERARCHY (Multi-tier)
────────────────────────────

L1: Go sync.Map (in-process, no GC pressure)
─────────────────────────────────────────────
• Key:   FNV-1a hash of (name + type + ecs_subnet)
• Value: Pre-encoded DNS response ([]byte, ready to send)
• TTL:   Min(SOA TTL, configured max)
• Size:  ~200MB (1M entries, 200 bytes each)
• Hit:   ~50 nanoseconds
• Eviction: LRU via access timestamp (atomic update)

L2: BadgerDB (local, persistent)
─────────────────────────────────
• Key:   Same hash
• Value: Compressed response + metadata
• Hit:   ~0.2ms (NVMe)
• Size:  ~1GB (5M entries)
• Use:   Survive restart, L1 miss fallback

L3: Redis Cluster (distributed, cross-node)
──────────────────────────────────────────
• Key:   Same hash
• Value: Response + hit count
• Hit:   ~0.5ms (localhost) / ~1ms (LAN)
• Use:   HA cache sharing, warm restart

EVICTION: LRU per tier, promote on hit, demote on miss
COHERENCE: TTL-based expiration, no strong consistency required
```

### 7.2 Cache Key Design

```go
// Cache key includes ECS subnet for proper isolation
func cacheKey(name string, qtype uint16, ecsSubnet *net.IPNet) uint64 {
    h := fnv.New64a()
    h.Write([]byte(name))
    h.Write([]byte{byte(qtype >> 8), byte(qtype)})
    if ecsSubnet != nil {
        h.Write([]byte(ecsSubnet.String()))
    }
    return h.Sum64()
}
```

---

## 8. Database Schema

### 8.1 PostgreSQL Schema

```sql
-- ============================================
-- PowerSVX SCHEMA - PostgreSQL (Single Tenant)
-- ============================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ZONES (Authoritative)
CREATE TABLE zones (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(20) DEFAULT 'native',
    dnssec_enabled BOOLEAN DEFAULT false,
    dnssec_algorithm VARCHAR(20) DEFAULT 'ECDSAP256SHA256',
    nsec_mode VARCHAR(10) DEFAULT 'nsec3',
    soa_serial BIGINT DEFAULT 1,
    soa_refresh INT DEFAULT 3600,
    soa_retry INT DEFAULT 600,
    soa_expire INT DEFAULT 86400,
    soa_minimum INT DEFAULT 3600,
    axfr_allow INET[],
    notify TEXT[],
    tsig_key_id UUID,
    split_horizon JSONB DEFAULT '{}',
    geo_config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- RECORDS
CREATE TABLE records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    zone_id UUID REFERENCES zones(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(10) NOT NULL,
    content TEXT NOT NULL,
    ttl INT DEFAULT 3600,
    prio INT DEFAULT 0,
    disabled BOOLEAN DEFAULT false,
    geo_tag VARCHAR(50),
    weight INT DEFAULT 0,
    healthcheck_enabled BOOLEAN DEFAULT false,
    healthcheck_url VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_records_zone_name ON records(zone_id, name);
CREATE INDEX idx_records_type ON records(type);
CREATE INDEX idx_records_geo ON records(geo_tag);

-- RPZ POLICIES (Metadata only, not entries)
CREATE TABLE rpz_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    policy_type VARCHAR(20) DEFAULT 'block',
    action VARCHAR(20) DEFAULT 'nxdomain',
    redirect_target INET,
    blocklist_url TEXT,
    blocklist_format VARCHAR(20) DEFAULT 'hosts',
    auto_update BOOLEAN DEFAULT true,
    update_interval INT DEFAULT 3600,
    last_updated TIMESTAMPTZ,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TSIG KEYS
CREATE TABLE tsig_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    algorithm VARCHAR(20) DEFAULT 'hmac-sha256',
    secret TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- QUERY LOGS (Partitioned)
CREATE TABLE query_logs (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_ip INET NOT NULL,
    client_subnet INET,
    query_name VARCHAR(255) NOT NULL,
    query_type VARCHAR(10) NOT NULL,
    response_code INT,
    response_time_ms INT,
    cached BOOLEAN DEFAULT false,
    blocked BOOLEAN DEFAULT false,
    blocklist_hit VARCHAR(255),
    server_node VARCHAR(64),
    protocol VARCHAR(10),
    dnssec_validated BOOLEAN,
    geo_country VARCHAR(2),
    geo_city VARCHAR(100),
    threat_score FLOAT,
    metadata JSONB DEFAULT '{}'
) PARTITION BY RANGE (timestamp);

CREATE TABLE query_logs_2026_07 PARTITION OF query_logs
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');

CREATE INDEX idx_query_logs_time ON query_logs(timestamp);
CREATE INDEX idx_query_logs_client ON query_logs(client_ip);
CREATE INDEX idx_query_logs_name ON query_logs(query_name);

-- ACME CHALLENGES
CREATE TABLE acme_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    key_authorization TEXT,
    validated BOOLEAN DEFAULT false,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_acme_token ON acme_challenges(token);

-- RATE LIMITING
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_subnet INET NOT NULL UNIQUE,
    queries_per_second INT DEFAULT 100,
    burst_size INT DEFAULT 200,
    block_duration INT DEFAULT 300,
    whitelist BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- PLUGINS
CREATE TABLE plugins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(20) DEFAULT 'lua',
    source_code TEXT,
    file_path VARCHAR(500),
    entry_point VARCHAR(255),
    enabled BOOLEAN DEFAULT false,
    execution_order INT DEFAULT 0,
    hook_points TEXT[],
    config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- SERVERS (Cluster nodes)
CREATE TABLE servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id VARCHAR(64) NOT NULL UNIQUE,
    hostname VARCHAR(255),
    listen_address INET,
    cluster_role VARCHAR(20) DEFAULT 'follower',
    raft_address INET,
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    metrics JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'active'
);

-- CONFIG (Key-Value runtime config)
CREATE TABLE config (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- FUNCTIONS & TRIGGERS
CREATE OR REPLACE FUNCTION update_soa_serial()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE zones SET soa_serial = soa_serial + 1, updated_at = NOW()
    WHERE id = NEW.zone_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_soa_serial
    AFTER INSERT OR UPDATE OR DELETE ON records
    FOR EACH ROW EXECUTE FUNCTION update_soa_serial();

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_zones_timestamp BEFORE UPDATE ON zones
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_records_timestamp BEFORE UPDATE ON records
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- SEED DATA
INSERT INTO config (key, value) VALUES
    ('version', '1.0.0'),
    ('setup_complete', 'false');
```

---

## 9. Configuration (TOML)

```toml
# /etc/PowerSVX/PowerSVX.toml

# ============================================
# SERVER
# ============================================
[server]
bind_address = "0.0.0.0"
udp_port = 53
tcp_port = 53
dot_port = 853
doh_port = 443
doq_port = 784
workers = 0  # 0 = auto (CPU cores)

[server.tls]
cert_file = "/etc/PowerSVX/certs/fullchain.pem"
key_file = "/etc/PowerSVX/certs/privkey.pem"
auto_tls = true  # ACME Let's Encrypt

# ============================================
# DATABASE
# ============================================
[database]
type = "postgres"
host = "localhost"
port = 5432
database = "PowerSVX"
user = "PowerSVX"
password = "${PG_PASSWORD}"
max_connections = 50

# ============================================
# CACHE
# ============================================
[cache]
type = "badger"
path = "/data/cache"
max_size_mb = 512
ttl_seconds = 300
negative_ttl = 60

[distributed_cache]
enabled = true
type = "redis"
host = "localhost"
port = 6379
password = "${REDIS_PASSWORD}"
db = 0

# ============================================
# RESOLVER
# ============================================
[resolver]
mode = "recursive"
forwarders = ["1.1.1.1:53", "8.8.8.8:53"]
ecs_enabled = true
ecs_prefix_v4 = 24
ecs_prefix_v6 = 56
dnssec_validation = true
qname_minimization = true
edns_buffer_size = 1232

# ============================================
# AUTHORITATIVE
# ============================================
[authoritative]
enabled = true
dnssec_signing = true
default_algorithm = "ECDSAP256SHA256"
nsec_mode = "nsec3"
auto_dnssec = true

# ============================================
# RPZ (20M Rules)
# ============================================
[rpz]
enabled = true
policies = [
    { name = "ads", source = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", format = "hosts", action = "nxdomain" },
    { name = "malware", source = "https://urlhaus.abuse.ch/downloads/hostfile/", format = "hosts", action = "nxdomain" }
]
update_interval = 3600
wildcard_support = true
hot_cache_size = 500000
bloom_filter_fp_rate = 0.001

# ============================================
# GEODNS
# ============================================
[geodns]
enabled = true
database_path = "/data/GeoLite2-City.mmdb"
default_tag = "default"
continents = ["AS", "EU", "NA", "SA", "AF", "OC", "AN"]

# ============================================
# SPLIT HORIZON
# ============================================
[split_horizon]
enabled = true
views = [
    { name = "internal", networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] },
    { name = "vpn", networks = ["100.64.0.0/10"] }
]

# ============================================
# CLUSTER (Raft)
# ============================================
[cluster]
enabled = true
node_id = "node1"
bind_address = "0.0.0.0:12000"
peers = ["node1:12000", "node2:12000", "node3:12000"]
data_dir = "/data/raft"

# ============================================
# API
# ============================================
[api]
rest_enabled = true
rest_bind = "0.0.0.0:5380"
grpc_enabled = true
grpc_bind = "0.0.0.0:50051"
auth_type = "token"
api_token = "${API_TOKEN}"

# ============================================
# LOGGING
# ============================================
[logging]
level = "info"
format = "json"
query_log_enabled = true
query_log_destination = "postgresql"
query_log_retention_days = 30

# ============================================
# METRICS
# ============================================
[metrics]
prometheus_enabled = true
prometheus_bind = "0.0.0.0:9100"
opentelemetry_enabled = true
otlp_endpoint = "http://localhost:4317"

# ============================================
# RATE LIMIT
# ============================================
[rate_limit]
enabled = true
default_qps = 100
default_burst = 200
block_duration = 300
whitelist = ["127.0.0.1/32", "10.0.0.0/8"]

# ============================================
# PLUGINS
# ============================================
[plugins]
enabled = true
directory = "/plugins"
hot_reload = true
max_execution_ms = 50

# ============================================
# ACME
# ============================================
[acme]
enabled = true
email = "admin@example.com"
accept_tos = true
provider = "letsencrypt"

# ============================================
# AI ANALYSIS
# ============================================
[ai]
enabled = false
model_endpoint = "http://localhost:8080"
anomaly_threshold = 0.85
```

---

## 10. Docker Compose Deployment

### 10.1 docker-compose.yml

```yaml
version: "3.9"

services:
  PowerSVX:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: PowerSVX
    hostname: dns-server
    network_mode: "host"
    environment:
      - PowerSVX_BIND_ADDRESS=0.0.0.0
      - PowerSVX_PG_HOST=postgres
      - PowerSVX_PG_PORT=5432
      - PowerSVX_PG_DB=PowerSVX
      - PowerSVX_PG_USER=PowerSVX
      - PowerSVX_PG_PASSWORD=${PG_PASSWORD}
      - PowerSVX_REDIS_HOST=redis
      - PowerSVX_REDIS_PORT=6379
      - PowerSVX_REDIS_PASSWORD=${REDIS_PASSWORD}
      - PowerSVX_BADGER_PATH=/data/cache
      - PowerSVX_LOG_LEVEL=info
      - PowerSVX_ENABLE_DNSSEC=true
      - PowerSVX_ENABLE_DOH=true
      - PowerSVX_ENABLE_DOT=true
      - PowerSVX_ENABLE_DOQ=true
      - PowerSVX_ENABLE_CLUSTER=true
      - PowerSVX_NODE_ID=${NODE_ID:-node1}
      - PowerSVX_CLUSTER_PEERS=${CLUSTER_PEERS}
      - PowerSVX_ACME_EMAIL=${ACME_EMAIL}
      - PowerSVX_THREAT_INTEL_FEEDS=${THREAT_FEEDS}
      - PowerSVX_AI_ANALYSIS=${ENABLE_AI:-false}
      - TZ=Asia/Jakarta
    volumes:
      - ./data/PowerSVX:/data
      - ./config:/etc/PowerSVX
      - ./logs:/var/log/PowerSVX
      - ./plugins:/plugins:ro
      - ./zones:/zones:ro
    security_opt:
      - no-new-privileges:true
    cap_add:
      - NET_BIND_SERVICE
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:5380/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:16-alpine
    container_name: PowerSVX-postgres
    environment:
      - POSTGRES_DB=PowerSVX
      - POSTGRES_USER=PowerSVX
      - POSTGRES_PASSWORD=${PG_PASSWORD}
      - PGDATA=/var/lib/postgresql/data/pgdata
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
      - ./configs/PowerSVX.sql:/docker-entrypoint-initdb.d/01-schema.sql:ro
      - ./configs/seed.sql:/docker-entrypoint-initdb.d/02-seed.sql:ro
    ports:
      - "127.0.0.1:5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U PowerSVX -d PowerSVX"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: PowerSVX-redis
    command: >
      redis-server
      --requirepass ${REDIS_PASSWORD}
      --appendonly yes
      --maxmemory 512mb
      --maxmemory-policy allkeys-lru
    volumes:
      - ./data/redis:/data
    ports:
      - "127.0.0.1:6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  grafana:
    image: grafana/grafana:11.0
    container_name: PowerSVX-grafana
    environment:
      - GF_SECURITY_ADMIN_USER=${GRAFANA_USER:-admin}
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
      - GF_SERVER_ROOT_URL=https://${DOMAIN}/grafana
    volumes:
      - ./data/grafana:/var/lib/grafana
      - ./configs/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./configs/grafana/datasources:/etc/grafana/provisioning/datasources:ro
    ports:
      - "127.0.0.1:3000:3000"
    depends_on:
      - prometheus
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:v2.53
    container_name: PowerSVX-prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
      - '--web.enable-lifecycle'
    volumes:
      - ./configs/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./data/prometheus:/prometheus
    ports:
      - "127.0.0.1:9090:9090"
    restart: unless-stopped

  jaeger:
    image: jaegertracing/all-in-one:1.57
    container_name: PowerSVX-jaeger
    environment:
      - COLLECTOR_OTLP_ENABLED=true
    ports:
      - "127.0.0.1:16686:16686"
      - "127.0.0.1:4317:4317"
      - "127.0.0.1:4318:4318"
    restart: unless-stopped

  threat-intel:
    image: alpine:latest
    container_name: PowerSVX-threat-intel
    command: >
      sh -c "
        apk add --no-cache curl jq &&
        while true; do
          curl -s https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts > /feeds/stevenblack.txt
          curl -s https://urlhaus.abuse.ch/downloads/hostfile/ > /feeds/urlhaus.txt
          curl -X POST http://PowerSVX:5380/api/v1/rpz/reload || true
          sleep 3600
        done
      "
    volumes:
      - ./data/threat-feeds:/feeds
    restart: unless-stopped

networks:
  default:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### 10.2 Environment File (.env)

```bash
# Database
PG_PASSWORD=YourStrongPostgresPassword123!
REDIS_PASSWORD=YourStrongRedisPassword456!

# Web UI
GRAFANA_USER=admin
GRAFANA_PASSWORD=YourGrafanaPassword789!

# Cluster
NODE_ID=node1
CLUSTER_PEERS=node1:12000,node2:12000,node3:12000

# ACME
ACME_EMAIL=admin@yourdomain.com

# Threat Intelligence
THREAT_FEEDS=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts,https://urlhaus.abuse.ch/downloads/hostfile/

# AI Analysis
ENABLE_AI=false

# Domain for reverse proxy
DOMAIN=dns.yourdomain.com

# API Token
API_TOKEN=YourSecureAPITokenHere
```

### 10.3 Dockerfile

```dockerfile
# Stage 1: Build
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git make gcc musl-dev linux-headers
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64     go build -ldflags='-w -s -extldflags "-static"'     -tags badger,pebble,lua,wasm     -o /build/PowerSVX ./cmd/PowerSVX

# Stage 2: Web UI Build
FROM node:20-alpine AS web-builder
WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 3: Runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -H -s /sbin/nologin PowerSVX
COPY --from=builder /build/PowerSVX /usr/local/bin/PowerSVX
RUN chmod +x /usr/local/bin/PowerSVX
COPY --from=web-builder /web/dist /usr/share/PowerSVX/web
RUN mkdir -p /data/cache /etc/PowerSVX /var/log/PowerSVX /plugins /zones     && chown -R PowerSVX:PowerSVX /data /var/log/PowerSVX
USER PowerSVX
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 784/udp 5380/tcp 50051/tcp 9100/tcp
ENTRYPOINT ["/usr/local/bin/PowerSVX"]
CMD ["--config", "/etc/PowerSVX/PowerSVX.toml"]
```

---

## 11. UI/UX Design

### 11.1 Design Philosophy

| Principle | Implementation |
|-----------|---------------|
| **Zero-config start** | Run -> automatically works as recursive resolver |
| **Progressive disclosure** | Basic features visible, advanced hidden but accessible |
| **Real-time feedback** | WebSocket for live query log, metrics, status |
| **Contextual actions** | Edit zone -> modal, no page navigation |
| **Visual hierarchy** | Consistent colors, clear status (Active/Warning/Error) |
| **Mobile responsive** | Dashboard accessible from phone for monitoring |
| **Auto theme** | Light/dark based on `prefers-color-scheme` |
| **Browser push** | Critical alerts via Service Worker |

### 11.2 Information Architecture

```
PowerSVX Web UI

SIDEBAR                    MAIN CONTENT AREA
─────────────────────────────────────────────────────────

Dashboard                  Status Bar (real-time WebSocket)
  Overview                   QPS | Cache Hit | Blocked | Cluster
  Real-time Metrics        
  Cluster Status           Query Volume Chart | Protocol Distribution
                             Top Blocked Domains | DNSSEC Status
Zones                        Live Query Stream (WebSocket)
  All Zones
  Add Zone (wizard)      
  Zone Transfer            
  DNSSEC Management        

Security                   
  RPZ / Blocklists         
  Rate Limiting            
  Threat Intelligence      
  DNSSEC Keys              

Network                    
  Split Horizon            
  GeoDNS                   
  Forwarders               
  ECS Settings             

Analytics                  
  Query Logs               
  Top Domains              
  Client Statistics        
  Blocked Queries          
  Performance              

Settings                   
  General                  
  Cache                    
  Encryption (DoT/DoH/DoQ) 
  Cluster                  
  API Tokens               
  Plugins                  
  Backup & Restore         

Tools                      
  DNS Lookup (dig-like)    
  Zone Transfer Test       
  DNSSEC Validator         
  ACME Challenge Status    

Help                       
  Documentation            
  API Reference            
  About                    
```

### 11.3 Design System

```
COLOR PALETTE
─────────────

Light Mode:
  Primary:    #2563EB (Blue-600)    → Actions, links, active states
  Success:    #10B981 (Emerald-500) → Online, valid, success
  Warning:    #F59E0B (Amber-500)   → Warning, pending, caution
  Danger:     #EF4444 (Red-500)     → Error, blocked, offline
  Info:       #3B82F6 (Blue-500)    → Info, neutral status
  Background: #F8FAFC (Slate-50)    → Page background
  Surface:    #FFFFFF (White)       → Cards, panels
  Border:     #E2E8F0 (Slate-200)   → Dividers, borders
  Text:       #0F172A (Slate-900)   → Primary text
  Muted:      #64748B (Slate-500)   → Secondary text, labels

Dark Mode:
  Background: #0F172A (Slate-900)
  Surface:    #1E293B (Slate-800)
  Border:     #334155 (Slate-700)
  Text:       #F8FAFC (Slate-50)
  Muted:      #94A3B8 (Slate-400)

TYPOGRAPHY
──────────
Font: Inter (Google Fonts)
H1: 24px/32px  font-weight: 700  → Page titles
H2: 20px/28px  font-weight: 600  → Section headers
H3: 16px/24px  font-weight: 600  → Card titles
Body: 14px/20px font-weight: 400  → General text
Mono: 13px/20px font-weight: 400  → Code, IPs, domains, logs

SPACING
───────
Base unit: 4px
Card padding: 24px (6 units)
Section gap: 24px
Inline gap: 8px (2 units)

SHADOWS
───────
Card: 0 1px 3px rgba(0,0,0,0.1), 0 1px 2px rgba(0,0,0,0.06)
Modal: 0 20px 25px rgba(0,0,0,0.1), 0 10px 10px rgba(0,0,0,0.04)
Dropdown: 0 10px 15px rgba(0,0,0,0.1)

ANIMATIONS
──────────
Page transition: 200ms ease-out
Modal open: 150ms cubic-bezier(0.4, 0, 0.2, 1)
Toast notification: 300ms slide-in
Live query row: flash green for 500ms on new entry
```

### 11.4 Responsive Breakpoints

| Breakpoint | Width | Layout |
|------------|-------|--------|
| Mobile | < 768px | Sidebar hidden (hamburger), cards stack, horizontal scroll status |
| Tablet | 768-1024px | Sidebar collapsible, 2-column grid |
| Desktop | > 1024px | Full sidebar, 3-4 column grid |

### 11.5 Browser Push Notification

```
Trigger Events:
  CRITICAL: Node down, certificate expired, DDoS detected
  WARNING:  Cache hit ratio < 80%, RPZ update failed
  INFO:     Successful cert renewal, cluster node joined

Permission Request (first critical event):
  "Node node2 is DOWN. Enable browser notifications?"
  [Enable Notifications] [Dismiss]

Push Payload:
{
  "title": "PowerSVX Alert",
  "body": "Node node2 is DOWN (5 min ago)",
  "icon": "/icon-192.png",
  "badge": "/badge-72.png",
  "tag": "node-down",
  "requireInteraction": true,
  "actions": [
    { "action": "view", "title": "View Dashboard" },
    { "action": "dismiss", "title": "Dismiss" }
  ]
}
```

---

## 12. API Specification

### 12.1 REST Endpoints

```
GET    /api/v1/health             → Liveness & dataplane health checks
GET    /api/v1/status             → Server status, uptime, version, dataplane stats
GET    /api/v1/metrics            → Prometheus-compatible metrics
GET    /api/v1/dashboard          → Aggregated dashboard data

GET    /api/v1/zones              → List authoritative zones
POST   /api/v1/zones              → Create zone
GET    /api/v1/zones/{id}         → Get zone details & records
PUT    /api/v1/zones/{id}         → Update zone SOA/DNSSEC meta
DELETE /api/v1/zones/{id}         → Delete zone
POST   /api/v1/zones/import       → Import RFC 1035 BIND zone file
GET    /api/v1/zones/{id}/export  → Export zone as RFC 1035 master text
GET    /api/v1/zones/{id}/dnssec  → Get DNSSEC status, DS & keys
POST   /api/v1/zones/{id}/dnssec  → Enable/configure DNSSEC (NSEC3, algo) or ZSK rollover

GET    /api/v1/zones/{id}/records → List records
POST   /api/v1/zones/{id}/records → Add record (validated via ValidateRecord)
PUT    /api/v1/zones/{id}/records → Update record inline (view/geo_tag/TTL)
DELETE /api/v1/zones/{id}/records → Delete record

GET    /api/v1/rpz                → RPZ & AXFR filter policies status
PUT    /api/v1/rpz                → Update RPZ policies & sync
POST   /api/v1/rpz                → Trigger RPZ/AXFR reload

GET    /api/v1/cache/stats        → 3-tier cache statistics (dnsdist, Unbound, Go L1)
GET    /api/v1/cache/inspect      → Search live Unbound cache dump entries
POST   /api/v1/cache/flush        → Flush all or selective cache tier / domain

GET    /api/v1/security/blocks    → Rate limit, auto-ban & dnsdist DynBlocks
POST   /api/v1/security/ban       → Ban CIDR / IP (live in ACL + dnsdist)
DELETE /api/v1/security/ban       → Unban CIDR / IP
POST   /api/v1/security/dynblocks/clear → Clear dnsdist dynamic blocks

GET    /api/v1/queries/live       → Query 20k in-memory ring buffer
GET    /api/v1/queries/stream     → Real-time SSE live query stream
GET    /api/v1/query-logs         → Historical PostgreSQL query logs (paginated)

POST   /api/v1/tools/lookup       → Multi-protocol DNS client (UDP/TCP/DoT/DoH)
POST   /api/v1/tools/trace        → Iterative root-to-authoritative trace

GET    /api/v1/auth/tokens        → List scoped API Bearer tokens
POST   /api/v1/auth/tokens        → Mint API Bearer token (shown once)
DELETE /api/v1/auth/tokens        → Revoke API Bearer token

GET    /api/v1/settings           → Get runtime settings
PUT    /api/v1/settings           → Update runtime settings & sync dataplanes
```

### 12.2 Authentication

```
Header: Authorization: Bearer <token>

OR mTLS:
  Client certificate required
  CN extracted as identity
```

---

## 13. WebSocket Events

### 13.1 Connection

```
ws://PowerSVX:5380/ws

Client -> Server:
  { "type": "subscribe", "channel": "queries" }
  { "type": "subscribe", "channel": "metrics" }
  { "type": "subscribe", "channel": "alerts" }
```

### 13.2 Event Types

```typescript
// Query event (real-time log)
interface QueryEvent {
  type: "query";
  timestamp: string;           // ISO 8601
  client_ip: string;
  client_subnet?: string;      // ECS
  query_name: string;
  query_type: string;          // A, AAAA, MX, etc.
  response_code: number;       // DNS RCODE
  response_time_ms: number;
  cached: boolean;
  blocked: boolean;
  blocklist_hit?: string;      // Which policy blocked
  protocol: "udp" | "tcp" | "dot" | "doh" | "doq";
  dnssec_validated?: boolean;
  geo_country?: string;        // ISO 3166-1 alpha-2
  geo_city?: string;
  threat_score?: number;       // 0.0 - 1.0
}

// Metric event (1-second aggregate)
interface MetricEvent {
  type: "metric";
  qps: number;
  cache_hit_ratio: number;     // 0.0 - 1.0
  blocked_queries: number;      // Per second
  active_connections: number;
  memory_usage_mb: number;
  goroutines: number;
}

// Alert event (push notification trigger)
interface AlertEvent {
  type: "alert";
  severity: "critical" | "warning" | "info";
  category: "node" | "certificate" | "security" | "performance";
  message: string;
  node_id?: string;
  details?: Record<string, unknown>;
}
```

---

## 14. Plugin System

### 14.1 Hook Points

```
PLUGIN LIFECYCLE
────────────────

1. ON_CONFIG_LOAD
   -> Modify configuration at startup

2. ON_QUERY_RECEIVED
   -> Inspect/modify query BEFORE processing
   -> Return: modified_msg, action (pass/block/rewrite)

3. ON_CACHE_LOOKUP
   -> Intercept cache check
   -> Return: cached_response, hit (true/false)

4. ON_RESOLUTION_START
   -> Called before recursive/auth resolution

5. ON_UPSTREAM_QUERY
   -> Modify upstream query (add ECS, etc)

6. ON_RESPONSE_READY
   -> Inspect/modify response BEFORE sending
   -> Return: modified_response

7. ON_CACHE_STORE
   -> Modify TTL, decide whether to cache

8. ON_QUERY_LOGGED
   -> Async hook after query is logged

9. ON_ZONE_CHANGED
   -> Called when zone is modified via API

10. ON_METRICS_EXPORT
    -> Add custom metrics to Prometheus
```

### 14.2 Lua Plugin Example

```lua
-- plugins/geoip_redirect.lua

function on_query_received(msg)
    local client_ip = msg.client_ip
    local geo = geoip.lookup(client_ip)

    if geo.country == "ID" then
        msg.add_edns0_option(ECS_OPTION, "1.2.3.0/24")
    end

    return msg
end

function on_response_ready(msg)
    -- Add custom header or modify response
    return msg
end
```

### 14.3 WASM Plugin Example

```rust
// plugins/rate_limiter.rs -> compile to WASM
// Runtime: wazero (Go)
// Sandboxed, any language that compiles to WASM
```

---

## 15. HA Clustering

### 15.1 Raft Cluster Architecture

```
RAFT CLUSTER
────────────

    ┌──────────┐         ┌──────────┐         ┌────────┐
    │  Node 1  │<------->│  Node 2  │<------->│ Node 3 │
    │ (Leader) │  Raft   │(Follower)│  Raft   │(Follower)
    │          │Consensus│         │Consensus│        │
    │ • Write  │         │ • Read  │         │ • Read │
    │ • Zone   │         │ • Cache │         │ • Cache│
    │   Changes│         │         │         │        │
    └────┬─────┘         └────┬─────┘         └───┬────┘
         │                    │                   │
         └────────────────────┴───────────────────┘
                          Anycast (BGP)
                          Virtual IP: 10.0.0.1

Sync:
  • Zone data via Raft log (strong consistency)
  • Cache via Redis (eventual consistency)
  • Query logs via PostgreSQL (async replication)

Failover:
  • Leader election < 1s
  • Read replicas serve traffic during election
  • Health checks via /api/health
```

### 15.2 Cluster Configuration

```toml
[cluster]
enabled = true
node_id = "node1"
bind_address = "0.0.0.0:12000"
peers = ["node1:12000", "node2:12000", "node3:12000"]
data_dir = "/data/raft"
```

---

## 16. Observability

### 16.1 Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `PowerSVX_queries_total` | Counter | `protocol`, `type`, `status` | Total queries |
| `PowerSVX_query_duration_seconds` | Histogram | `protocol` | Response time |
| `PowerSVX_cache_hits_total` | Counter | `cache_type` | Cache hit count |
| `PowerSVX_cache_misses_total` | Counter | `cache_type` | Cache miss count |
| `PowerSVX_dnssec_validated_total` | Counter | `result` | DNSSEC validation |
| `PowerSVX_rpz_blocked_total` | Counter | `policy`, `domain` | Blocked queries |
| `PowerSVX_geodns_routed_total` | Counter | `continent`, `country` | GeoDNS routing |
| `PowerSVX_cluster_nodes` | Gauge | `role` | Active cluster nodes |
| `PowerSVX_plugin_execution_ms` | Histogram | `plugin`, `hook` | Plugin latency |
| `PowerSVX_ai_anomaly_score` | Gauge | `client_subnet` | AI threat score |

### 16.2 Grafana Dashboards

Pre-built dashboards:
- **Overview**: QPS, cache hit ratio, blocked queries, cluster health
- **DNS Performance**: Latency percentiles (p50, p95, p99) per protocol
- **RPZ Effectiveness**: Blocked queries per policy, top blocked domains
- **GeoDNS**: Heatmap of queries per region, routing decisions
- **Cluster**: Raft consensus status, node latency, leader election events
- **Security**: Threat score distribution, DDoS pattern detection
- **DNSSEC**: Validation rate, signing performance, key rollover status

### 16.3 OpenTelemetry Tracing

```
Trace Structure:
  dns.query (root span)
    ├── rate_limit.check
    ├── rpz.lookup
    │   ├── radix_tree.check
    │   └── bloom_filter.check (optional)
    ├── cache.lookup
    │   ├── l1.syncmap
    │   └── l2.badger (optional)
    ├── resolution
    │   ├── authoritative.lookup (or)
    │   └── recursive.resolve
    │       ├── upstream.query
    │       └── dnssec.validate
    ├── dnssec.sign (if authoritative)
    ├── plugin.execute
    └── response.encode
```

---

## 17. Security Considerations

### 17.1 Network Security

| Layer | Protection |
|-------|-----------|
| DNS (UDP/TCP) | Rate limiting, RPZ filtering, query validation |
| DoT | TLS 1.3, certificate pinning, SNI validation |
| DoH | TLS 1.3, HTTP/2 multiplexing, path validation |
| DoQ | QUIC 0-RTT mitigation, connection migration |
| API | Bearer token or mTLS, CORS, CSRF protection |

### 17.2 Data Security

- **PostgreSQL**: TLS connection, prepared statements (SQL injection prevention)
- **Redis**: AUTH password, TLS optional
- **BadgerDB**: Filesystem encryption at rest (optional)
- **Query Logs**: PII masking option, retention policy

### 17.3 DNSSEC Security

- Algorithm 13 (ECDSAP256SHA256) — recommended by RFC 8624
- Automatic ZSK rollover (every 90 days)
- KSK rollover with DS record update notification
- NSEC3 with opt-out for large zones

---

## 18. Deployment Guide

### 18.1 Quick Start (Standalone)

```bash
# 1. Clone repository
git clone https://github.com/your-org/PowerSVX.git
cd PowerSVX

# 2. Configure environment
cp .env.example .env
# Edit .env with your passwords

# 3. Start services
docker-compose up -d

# 4. Access UI
open http://localhost:5380

# 5. Default login
# API Token from .env
```

### 18.2 Cluster Deployment

```bash
# Node 1 (Leader)
NODE_ID=node1 CLUSTER_PEERS=node1:12000,node2:12000,node3:12000 docker-compose up -d

# Node 2 (Follower)
NODE_ID=node2 CLUSTER_PEERS=node1:12000,node2:12000,node3:12000 docker-compose up -d

# Node 3 (Follower)
NODE_ID=node3 CLUSTER_PEERS=node1:12000,node2:12000,node3:12000 docker-compose up -d

# Verify cluster
 curl http://node1:5380/api/v1/cluster/nodes
```

### 18.3 System Requirements

| Deployment | CPU | RAM | Disk | Network |
|------------|-----|-----|------|---------|
| Standalone | 2 cores | 2GB | 20GB SSD | 1Gbps |
| Cluster (per node) | 4 cores | 4GB | 50GB NVMe | 10Gbps |
| Cache-only (20M RPZ) | 8 cores | 8GB | 100GB NVMe | 10Gbps |

---

## 19. Monitoring & Alerting

### 19.1 Health Checks

```
Endpoint: GET /api/v1/health

Response:
{
  "status": "healthy",  // healthy | degraded | unhealthy
  "checks": {
    "dns_udp": { "status": "pass", "latency_ms": 0.5 },
    "dns_tcp": { "status": "pass", "latency_ms": 1.2 },
    "database": { "status": "pass", "latency_ms": 2.1 },
    "cache": { "status": "pass", "hit_ratio": 0.94 },
    "cluster": { "status": "pass", "role": "leader", "peers": 3 }
  },
  "uptime_seconds": 1209600
}
```

### 19.2 Alert Rules (Prometheus)

```yaml
groups:
  - name: PowerSVX
    rules:
      - alert: HighQueryLatency
        expr: histogram_quantile(0.99, PowerSVX_query_duration_seconds_bucket) > 0.005
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "DNS query latency p99 > 5ms"

      - alert: NodeDown
        expr: PowerSVX_cluster_nodes{role="leader"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "No cluster leader elected"

      - alert: CertificateExpiring
        expr: PowerSVX_certificate_expiry_seconds < 86400 * 7
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "TLS certificate expires in < 7 days"
```

---

## 20. Roadmap

### Phase 1: Foundation (Weeks 1-4)
- [ ] Project structure & CI/CD
- [ ] UDP/TCP listener with miekg/dns
- [ ] Recursive resolver with root hints
- [ ] BadgerDB cache layer
- [ ] PostgreSQL backend

### Phase 2: Security & Encryption (Weeks 5-8)
- [ ] DoT (RFC 7858)
- [ ] DoH/DoH3 with HTTP/3
- [ ] DoQ with quic-go
- [ ] DNSSEC signing & validation
- [ ] TSIG key management

### Phase 3: Advanced Features (Weeks 9-14)
- [ ] RPZ engine with 20M rule support
- [ ] GeoDNS with MaxMind/GeoIP2
- [ ] ECS (EDNS Client Subnet) support
- [ ] Split Horizon DNS
- [ ] Rate limiting

### Phase 4: Enterprise (Weeks 15-20)
- [ ] Raft-based clustering
- [ ] REST API & gRPC
- [ ] React Web UI
- [ ] Prometheus & OpenTelemetry
- [ ] Query logging & analytics

### Phase 5: Ecosystem (Weeks 21-26)
- [ ] Lua/WASM plugin system
- [ ] ACME DNS-01 challenge
- [ ] Threat intelligence feeds
- [ ] AI query analysis (anomaly detection)
- [ ] Grafana dashboards
- [ ] Browser push notifications

---

## Appendix A: Comparison Matrix

| Feature | Technitium | Unbound | CoreDNS | PowerSVX (existing) | **PowerSVX (This)** |
|---------|-----------|---------|---------|---------------------|---------------------|
| Language | C#/.NET | C | Go | C++ | **Go** |
| UI | Modern | CLI only | CLI only | CLI/API only | **React Modern** |
| Recursive | Native | Native | Via plugin | Separate recursor | **Built-in** |
| DoQ | Yes | No | Yes | No | **Native** |
| Plugin | No | No | Go compile | Lua | **Lua + WASM hot-reload** |
| Clustering | v14+ | No | No | Complex | **Raft native** |
| RPZ Scale | ~100K | ~100K | ~100K | ~100K | **20M rules** |
| Cache Latency | ~3ms | ~5ms | ~5ms | ~5ms | **<5ms p99** |

---

## Appendix B: Glossary

| Term | Definition |
|------|-----------|
| **RPZ** | Response Policy Zone — DNS-based blocklist mechanism |
| **DoT** | DNS-over-TLS — encrypted DNS on port 853 |
| **DoH** | DNS-over-HTTPS — encrypted DNS over HTTPS |
| **DoQ** | DNS-over-QUIC — encrypted DNS over QUIC (RFC 9250) |
| **ECS** | EDNS Client Subnet — forward client subnet to upstream |
| **DNSSEC** | DNS Security Extensions — cryptographic authentication |
| **ZSK** | Zone Signing Key — signs zone records |
| **KSK** | Key Signing Key — signs ZSK, published as DS record |
| **NSEC3** | Next Secure 3 — authenticated denial of existence |
| **Raft** | Consensus algorithm for distributed systems |
| **RCU** | Read-Copy-Update — lock-free data structure update |
| **LSM** | Log-Structured Merge — write-optimized storage (BadgerDB) |
| **Bloom Filter** | Probabilistic membership test, O(1) lookup |
| **Cuckoo Filter** | Probabilistic membership test with deletion support |

---

*Document Version: 1.0.0*
*Last Updated: 2026-07-20*
*License: MIT*
