---
status: accepted
---

# The primary signs, and secondaries serve the signatures they receive

The Auth Backend signs an Authoritative Zone at query time, but a zone transfer was built from the stored records only. A secondary that pulled a signed zone got no DNSKEY, no RRSIG and no NSEC or NSEC3, so it could not serve answers that validate against the DS published for the primary's keys. A transfer of a signed zone now carries what the primary answers to any resolver, and a secondary serves what it receives. A Secondary Zone of this software does the same and never signs.

## Considered Options

- **Inline signing on the secondary, with keys shared out of band.** Rejected: key distribution, a second place where the signing key can leak, and a secondary whose signatures differ from the primary's.
- **The primary signs; the transfer carries the signed zone.** Chosen.

## What a transfer of a signed zone carries

AXFR, and the full-zone answer an IXFR gets, send in one stream (first and last RR the SOA): the DNSKEY RRset (signed by the key signing key), the signed NSEC3PARAM for an NSEC3 zone, every RRset of the zone with its RRSIG (zone signing key), and the whole NSEC or NSEC3 chain with an RRSIG on each record. The same keys, algorithm, NSEC or NSEC3 policy and RRSIG fields as in query answers are used; only the validity window differs (below). An unsigned zone is transferred exactly as before. Private keys, the key policy file and the refresh state never leave the primary. The access rules (`allow_axfr`, `allow_from`, the TSIG check) run before any of this and are unchanged.

A signature covers one RRset, so a signed zone goes out as the requesting client's view of it: the records of the split-horizon view its address is in, with the GeoDNS default answer. An unsigned zone still goes out with the records of every view, as before. Stored DNSSEC records (DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM) of a hosted zone are ignored for a signed zone: the transfer makes its own.

The stream is cut into messages of at most 16 KiB of answers over TCP (a message is limited to 64 KiB, and a signed zone does not fit), and the zone is signed while it is sent; only the owner-name map for the denial chain is held besides the snapshot of the zone's records. The snapshot is taken once under the store lock, so a transfer is consistent if the zone changes while it is sent.

## IXFR

An IXFR of a signed zone is answered with the whole zone (RFC 1995 section 4 allows it), and with the SOA alone when the client's serial is current. Deltas would have to carry the changed RRSIGs and chain records, and the signatures change with no record change (a new refresh interval, a rolled key), so a delta journal would have to learn about all of them; one wrong delta leaves a secondary with stale or missing signatures, and a whole-zone answer cannot. An unsigned zone keeps its real IXFR deltas.

## How the signatures a secondary holds stay valid

A secondary keeps what it pulled until the SOA serial changes, so signatures made for a transfer are not made "now" as query answers are:

- Time is cut into refresh intervals counted from the Unix epoch. All signatures made in one interval share one window: it starts one hour before the interval (clock skew, RFC 6781) and ends *validity* after its start.
- A secondary that pulls at any moment of an interval holds signatures with at least *validity* minus *refresh* left.
- The Auth Backend bumps the SOA serial and sends NOTIFY when an interval ends, so secondaries pull the next window. It bumps the serial for the same reason when a key is rolled, when a zone is newly signed, and when the NSEC or NSEC3 policy or salt changes. The last state a serial was bumped for is kept in `<data>/dnssec/<zone>/transfer-state`, so a restart does not bump again and a downtime across a boundary bumps once.
- A check runs every ten minutes (`RunSignatureRefresh`), so a serial moves at most ten minutes after an interval ends.

What the operator must know: `[transfer] signature_validity_days` (default 30) and `signature_refresh_days` (default 7). Refresh is held to at most half of validity. A secondary must pull within *validity* minus *refresh* days (23 by default) of the last serial it saw, or its signatures expire; its SOA refresh and retry timers are far shorter than that. Transfers of a large zone cost one signature per RRset and per chain record.

## Secondary Zones

A Secondary Zone stores the DNSKEY, RRSIG, NSEC, NSEC3 and NSEC3PARAM records it receives as ordinary zone data, in the same store and files as the rest of the zone; no new notion is added to the store. The handler treats a zone as pre-signed when it is a Secondary Zone:

- It never signs it, even when keys exist for the same name in the local key store.
- A query with DO gets the stored RRSIGs of every RRset in the answer, and for a negative answer or a wildcard expansion the stored NSEC or NSEC3 records that prove it, chosen by the rules of RFC 4035 section 3.1.3 and RFC 5155 section 7.2, with their RRSIGs and the SOA's RRSIG. NSEC3 hash parameters come from the records themselves.
- A query without DO is answered as before.
- A transfer out of a Secondary Zone sends the stored records, signatures included.

The secondary's refresh is unchanged: the SOA check, then an IXFR request; the whole-zone answer is installed like an AXFR.

## Consequences

- A secondary of any make (BIND, Knot, PowerDNS) serves the zone, and `delv` validates its answers against the primary's DS (`test/xfersigned`).
- The serial of a signed zone moves once per refresh interval even if no record changes.
- A secondary with views or per-location answers sees the single view its address matches; per-view signed zones are not transferable as a union.
