# Upgrading a node from 1.x to 2.0

PowerSVX 2.0 answers customer queries with dnsdist and Unbound only (ADR-0001). The Go process is the Control Plane and the Auth Backend. Read `CHANGELOG.md` (2.0.0, "Breaking changes") first.

## Why `latest` does not move to 2.0.0

Watchtower pulls the image tag `latest`. A node that still runs a removed Dataplane mode and received the 2.0 Control Plane by itself would stop answering customer queries. So the release workflow moves `latest` only for 1.x tags. Images `2.0.0` and `2.0` exist. A node is upgraded on purpose, with `apply-update.sh`, as below. When every node is migrated, move `latest` by running the "Release & Docker CD" workflow by hand from the `v2.0.0` tag with `promote_latest` set.

Watchtower also needs registry credentials on the node (see "Watchtower and the private GHCR image" in `docs/PRODUCTION.md`), or it never updates anything.

## Before you start (per node)

1. **Dataplane mode.** `sh deploy/linux/dataplane-guard.sh <project dir>` must pass. It refuses the Go query path and Unbound on the public port; move such a node to dnsdist first on 1.x.
2. **TSIG.** With the default `require_tsig = true`, a zone transfer or dynamic update request without a TSIG record is refused. Check that every secondary and updater signs its requests, or set `require_tsig = false` for the section on purpose.
3. **Transfers carry one view.** A secondary now receives the view and GeoDNS answer for its own address. A secondary that needed every view must pull from an address in each view, or use file export.
4. **Backup and a way back.** Copy `configs/`, `.env`, `docker-compose.yml` and `data/` somewhere safe, and save the running image as a file: `docker save ghcr.io/hendrax5/powersvx:latest -o powersvx-1.x-image.tar`. `apply-update.sh` prunes unused images afterwards, so a `docker tag` alone does not survive it.
5. **Zones move from Postgres to files.** The first start of 2.0 exports the `zones` and `records` tables to per-zone files once (ADR-0002); after that the tables are never read, and every later zone change lives only in the files. Records marked `disabled` in the old table are not exported (they were never served). Keep the Postgres data volume as it is until you are sure you will not go back.
6. Run this on a node that serves no customers first.

## Upgrade

```bash
cd <project dir>
git fetch --tags && git checkout v2.0.0          # or copy the release files
POWERSVX_PULL_IMAGE=1 POWERSVX_IMAGE_TAG=2.0.0 bash deploy/linux/apply-update.sh
```

Without `POWERSVX_PULL_IMAGE=1` the Control Plane image is built on the node from the checkout. Put `POWERSVX_PROFILE=core` in `.env` to run the Core Profile (dnsdist, Unbound, Control Plane); unset means the full stack. Postgres is optional: a node that has it keeps running it.

What the script does, in this order: checks the Dataplane mode, applies OS hardening (narrows the `NOTRACK` rule for UDP/53 to packets for the node), generates the Unbound and dnsdist configuration, checks the Unbound configuration, starts the new Control Plane and waits for it to be healthy, then replaces the dnsdist configuration and recreates Unbound and dnsdist. It ends by checking that port 53 answers and that a fresh name resolves by recursion. Expect:

- A node whose `.env` has no dnsdist web password or API key gets random ones (file mode 600). For a few seconds the Control Plane's calls to the dnsdist web API can answer 401 while the two settle; DNS is not affected.
- On the first start the Control Plane may rebuild the Filter (about two minutes for 10 million names, about 200 MB of memory) and may log `config key ignored since version 2` for keys listed in `docs/CONFIG-REMOVED.md`.
- A WARNING that Watchtower cannot pull the image, if the node has no registry credentials.

## After

```bash
bash deploy/linux/dns-ready.sh -r example.com          # port 53 answers and recursion works
bash deploy/linux/check-notrack.sh                     # the broad NOTRACK rule is gone
bash deploy/linux/watchtower-health.sh                 # Watchtower can pull (if you rely on it)
curl -s http://127.0.0.1:5380/api/v1/health            # version, Filter last_sync, Unbound state
```

## Roll back

Restore the backed-up `configs/`, `.env`, `docker-compose.yml` and `data/`, load the saved image (`docker load -i powersvx-1.x-image.tar`), and run `docker compose up -d --force-recreate` for the stack. 1.x reads zones from Postgres, which 2.0 stopped reading after its first export: **zone changes made after the upgrade are not in Postgres and are lost on rollback** unless you copy them back by hand (the per-zone files under `data/zones/` hold them, and the REST export lists them).
