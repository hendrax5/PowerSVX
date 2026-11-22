# Reference Load benchmark

Measures a DNS server under the Reference Load and writes one results file per run. Use it to take a Baseline and to judge every tuning change against it.

It reports the highest query rate at which the server keeps up (loss at or below 0.1% and p99 latency at or below 5 ms), the latency percentiles at that rate, and per-service memory on the server.

## Before you start

- Use two machines: the server under test and a separate load generator. A run with both on one host says nothing about the server.
- Use a lab node, not one that serves customers.
- Turn query logging off on the server.
- The load generator needs Docker. The server needs nothing extra.

## 1. Build the load generator image

From the repository root, on the load generator:

```bash
docker build -f scripts/bench/Dockerfile -t powersvx-bench .
```

If the build cannot resolve package mirrors, add `--network host`. This was seen on a node set up by `bootstrap-node.sh`, where containers on the default bridge could not resolve names.

## 2. Get the two name lists

- **Popular names**, most popular first: a public top-sites list such as [Tranco](https://tranco-list.eu). Both plain names and `rank,name` CSV work. Note the list's ID or date in the run note so the run can be repeated.
- **Filter names**, one per line: a sample of the names the Filter on the server blocks. On a node, the per-policy feed caches under `data/blocklist/feeds/` are in this format (wildcard entries such as `*.example.com` are accepted). They hold millions of names; take a sample, for example every 300th line.

Neither list contains customer data. Do not use customer query logs.

## 3. Generate the query set

```bash
docker run --rm -v "$PWD:/work" powersvx-bench -c \
  '/opt/bench/gen-queryset.sh -p popular.csv -f filter.txt -s 1 > queries.txt'
```

Defaults: one million queries, the top 100,000 popular names with a Zipf distribution, 5% Filter names, 5% names that do not exist, and 60% A, 30% AAAA, 10% HTTPS. `gen-queryset.sh` lists the options in its header. If you have real ratios from a production node, set `-F` and `-X` to match.

The same inputs and seed always produce the same file. The results file stores its SHA-256.

## 4. Run

```bash
docker run --rm --network host \
  -v "$PWD:/work" -v "$HOME/.ssh:/root/.ssh:ro" powersvx-bench -c \
  '/opt/bench/run.sh -s 192.0.2.10 -S admin@192.0.2.10 -d queries.txt -l powersvx-full -n "Tranco 2026-11-01, core profile"'
```

- `-s` is the server's address. `-S` is an ssh destination for the same server; with it the run records CPU count, memory, kernel, container images and per-service memory under load. Without `-S` those fields stay empty.
- `-l` names the run. The results land in `./results/<label>-<UTC time>.json`.
- A default run takes roughly eight minutes: a warm-up that sends every distinct query once at 2000 qps, up to eight 30-second search steps, and a 120-second measurement.

Commit the results file under `docs/bench/`.

## Reading a results file

| Field | Meaning |
|---|---|
| `max_qps` | Answered queries per second in the final measurement |
| `loss_pct` | Share of queries not answered within 2 seconds in the final measurement |
| `passed` | Whether the final measurement stayed within the loss and p99 limits |
| `limited_by` | `server`: the search found the rate above which the server loses queries or answers late. `load generator`: the server kept up with everything this machine could send, so the true limit is higher |
| `latency_ms` | Average and percentiles over all answers in the final measurement |
| `search_steps` | Every rate that was tried, with the loss and p99 seen at each |
| `server.memory_under_load` | `docker stats` on the server, sampled halfway through the final measurement |

Things to keep in mind:

- Overload shows up as latency before it shows up as loss. dnsperf keeps at most `-q` queries outstanding, so a saturated server answers everything, late. That is why p99 is part of the limit; `-P 0` turns it off.
- Near the limit, p99 varies from step to step. Use longer steps (`-t`) for a number you intend to publish.
- When `limited_by` is `load generator`, the number is a floor, not the server's limit. Add threads (`-T`), clients (`-c`) or a second load generator before comparing two systems.
- Latency covers cache hits and misses together. The client cannot tell them apart, and after warm-up nearly all answers come from cache.
- Cache misses go to the real internet. The warm-up rate (`-W`, default 2000 qps) is kept low on purpose; do not raise it carelessly.
- Names that do not exist all sit under one made-up top-level name and come from a fixed pool, so the run does not flood the root servers with junk.

## Comparing PowerSVX with Technitium

Both systems run on the same server, one after the other, at two sizes: `full` (the whole machine) and `small` (2 CPUs and 2 GB). Everything below runs on the server, as root, from a checkout of this repository.

### The two sizes

`small` is a cgroup slice shared by everything under test, so the three PowerSVX containers together are held to the same CPUs and memory as the single Technitium container. CPUs are pinned with a cpuset (the first N CPUs), so the system sees N CPUs, as on a real N-vCPU node.

```bash
sudo scripts/bench/size-slice.sh up            # 2 CPUs, 2048 MB, no swap; -c and -m change them
sudo scripts/bench/size-slice.sh status
sudo scripts/bench/size-slice.sh down          # refuses while anything still runs in the slice
```

It needs cgroup v2 and systemd 244 or newer. A reboot removes the slice. On a 12-vCPU node it was checked to give a container 2 CPUs (four busy loops used exactly 12 CPU-seconds in 6 seconds) and to kill a 3 GB allocation at the 2 GB cap.

Keep the load generator off the slice's CPUs, or better on another machine: `docker run --cpuset-cpus 4-9 ...` for a same-host check.

### Technitium

```bash
sudo scripts/bench/technitium.sh up -f filter.txt -a 192.0.2.20/32 \
     [-b 192.0.2.10] [-z small]
sudo scripts/bench/technitium.sh settings > results/technitium-settings.json
sudo scripts/bench/technitium.sh down
```

`-f` is the same Filter file you gave `gen-queryset.sh`. `-a` is required: it is the list of networks allowed to recurse, normally the load generator's address. There is no open-resolver default. The script refuses to start if port 53 is taken, so stop PowerSVX's dnsdist first (this is the host-network mode used for measurements; `-N bridge` is only for functional checks).

`up` ends with checks through the server itself: a Filter name must get the sinkhole address, `example.com` must resolve by recursion, and the DNS port must answer from outside the container. It fails otherwise.

What the fair configuration is, and why:

| Setting | Value | Why |
|---|---|---|
| Version | pinned release 15.6.2 (image digest recorded by `settings`) | repeatable; bump it in its own change |
| Resolution | full recursion from the root servers, no forwarders | as PowerSVX's Unbound |
| Recursion | allowed only for `-a` | never an open resolver |
| Filter | the Filter names as a block list, answered with the sinkhole addresses: A to `139.255.196.196`, AAAA to `::`, other types NOERROR with no data | the same answers as the dnsdist rules; names match their subdomains in both |
| Query log | off (`logQueries=false`) | per-query logging costs throughput and is off in the PowerSVX runs |
| Cache | 1,000,000 entries, minimum TTL 60 s | the default of 10,000 entries cannot hold the query set; 60 s matches dnsdist's packet cache |
| Everything else | the release's defaults | including dashboard statistics, which stay on |
| Web console | 127.0.0.1 only; the admin password is generated into the state directory and never printed | the console is not part of the measurement and must not be exposed |

Things that are not equal, so say them when you quote a result:

- Technitium keeps its dashboard statistics; PowerSVX keeps its own counters. Neither is turned off.
- Technitium's maximum record TTL is 7 days against dnsdist's 1 day; names in the query set are all re-asked within one run, so it does not change what is measured.
- Technitium's own default is to listen on all addresses on port 53, and the script only moves it to the address and port you asked for after it has started (there is no environment variable for this). This was not observed to disturb a host where dnsdist held specific addresses on port 53, but do not start it on a host where another service must keep answering on port 53.

### PowerSVX at small size

Until Postgres is optional, the Core Profile needs four containers for this benchmark: dnsdist, Unbound, the Control Plane and Postgres (Watchtower is Core too, but is left out of the slice). Name them so that the Observability Profile (Prometheus, Grafana, node-exporter) stays stopped, and size the configuration for the small node:

```bash
sudo scripts/bench/size-slice.sh up
eval "$(scripts/bench/size-slice.sh env)"       # POWERSVX_HOST_CPUS=2, POWERSVX_HOST_MEM_MB=2048
bash deploy/linux/gen-unbound-conf.sh && bash deploy/linux/gen-dnsdist-conf.sh
eval "$(deploy/linux/calc-mem-env.sh)"
docker compose -f docker-compose.yml -f deploy/linux/docker-compose.host.yml \
  -f deploy/linux/docker-compose.bench-small.yml up -d dnsdist unbound powersvx postgres
```

The generators size caches and thread counts from the host's CPUs and memory. Without `POWERSVX_HOST_CPUS` and `POWERSVX_HOST_MEM_MB` a 2 GB slice on an 8 GB host would run a configuration meant for 8 GB.

### Running and comparing

Run `run.sh` twice from the load generator with the same query set and settings, changing only the system:

```bash
run.sh -s SERVER -S admin@SERVER -d queries.txt -l powersvx-small -y powersvx   -Z small \
       -R 'dnsdist|unbound|^powersvx$|postgres'
run.sh -s SERVER -S admin@SERVER -d queries.txt -l technitium-small -y technitium -Z small \
       -R '^technitium-bench$'
compare.sh results/powersvx-small-*.json results/technitium-small-*.json
```

`-S` (ssh with a key; password prompts are not supported) is what records the server's CPUs, memory and per-container memory. `-R` limits that to the containers that belong to the system, so Prometheus or Grafana running on the same host do not count against it. Memory is `docker stats` usage, which excludes reclaimable page cache.

`compare.sh` prints the two runs side by side and ends with `COMPARABLE: yes` or `no`. It says no, and exits 1, when the query sets, the load generator settings, the dnsperf versions, the sizes, the loss and p99 limits or the server hardware differ. It adds notes when the load generator was the limit, when a final measurement fell outside the limits, and when memory or hardware was not recorded.

### The Filter: sample or full

A 1-in-300 sample of the Filter (about 50,000 names) is enough to measure query throughput. It is not enough to compare memory: the production Filter has about 20 million names, and holding them is a large part of both systems' footprint. For the memory comparison use the full feed on both sides. Technitium loads it into memory; at the `small` size that may not fit in 2 GB, which is itself a result worth recording.
