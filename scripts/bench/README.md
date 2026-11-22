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

## Comparing two systems

Run the same query set, from the same load generator, against each system on the same hardware, one after the other. Change only the label. Everything else in the two results files should match, including `query_set.sha256` and the `load_generator` block.
