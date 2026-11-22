---
status: accepted
---

# Authoritative zones live in files; Postgres is optional

Postgres held two things: authoritative zones with their records, and the query log. Everything else the control plane persists (users, tokens, settings, filter policies, secondary zones, DNSSEC keys) was already a JSON file in the data directory. That made a full database server mandatory on every node just to keep zones across a restart, while the product we measure ourselves against stores everything in files. Authoritative zones move to one JSON file per zone, written atomically, the same way secondary zones are stored. Postgres remains only as the store for query-log history and belongs to the Observability Profile.

## Considered Options

- **Embedded SQLite.** Rejected: zones are loaded whole into memory at start and rewritten whole on change, so nothing needs a query engine, and the per-zone file mechanism already exists and is tested for secondary zones.
- **Keep Postgres in the Core Profile with a memory cap.** Rejected: it stays a boot-time point of failure and the largest fixed memory cost on a small node.

## Consequences

- The first start of a version with this change exports the `zones` and `records` tables to files once. After that the tables are never read.
- A node with no Postgres has no query-log history, only the live sampled stream.
- Records marked `disabled` in the old `records` table are not exported: they were never served, and nothing in the API or console can set that flag.
