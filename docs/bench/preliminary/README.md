# Preliminary lab runs, 2026-11-22

These are not a Baseline. No Technitium run exists yet, and the server details in these files are empty because the runs did not use ssh to reach the server.

Server under test: one lab node, 12 vCPU (Xeon E5-2680 v4, KVM), 8 GB, stock generated dnsdist and Unbound configuration, nothing else changed. Query set: 500,000 lines, SHA-256 prefix `3913803e7e0422e0`, built from the Tranco top 10,000 and a 1-in-300 sample of the Filter feed.

| File | Load generator | Highest rate within loss <= 0.1% and p99 <= 5 ms | Note |
|---|---|---|---|
| `smoke-samehost-...121454Z.json` | same host as the server | about 34,000 qps | one dnsdist thread at about 70% of a core, the others idle |
| `twonode-stock-...124935Z.json` | second node, 0.1 ms away | about 18,600 qps | the p99 per step is not monotonic: 15.7k qps gave 4.2 ms, 19.6k gave 5.1 ms, 31k gave 8.2 ms |

Two further fixed-rate runs from the second node at 25,000 qps answered about 24,700-24,800 qps with p99 7.3 ms and 4.6 ms and loss of about 0.02%.

Read the maximum as "somewhere between 15,000 and 30,000 qps depending on the p99 criterion", not as a sharp limit. p99 sits near the 5 ms threshold over that whole range and varies run to run, so a single 20-second step cannot place the limit precisely. A publishable number needs longer steps and repeated runs.

## 2026-11-23: PowerSVX at full size on the 2.0 integration build, and a failed Technitium comparison

Still not a Baseline. One valid PowerSVX run exists; the Technitium run did not produce a usable result.

Server: the same lab node (12 vCPU, 8 GB), updated with `apply-update.sh` to the integration branch, Core Profile (Postgres stopped for the run), query log off. Load generator: the second node (8 vCPU). Query set: 1,000,000 lines, SHA-256 prefix `515c39de3140d9e7`, from the Tranco top 100,000 (zip SHA-256 prefix `7591e81e3d9150b7`, fetched 2026-11-23) and a 1-in-300 sample of the node's Filter (34,062 of 10,218,854 names).

| File | Highest rate within loss <= 0.1% and p99 <= 5 ms | Note |
|---|---|---|
| `powersvx-full-20261123T144133Z.json` | 19,108 qps, loss 0.046%, p99 0.64 ms | `limited_by: server`. The server details in the file are empty (no ssh). Warm-up at the default 2000 qps |

Memory under load, sampled from `docker stats` every 10 s on the server (peak over the run, page cache excluded): Control Plane 8 MiB, dnsdist 93 MiB, Unbound 98 MiB, about 200 MiB together. This is a lab sample, not a results-file field.

Steps of the rate search were not monotonic again (26,033 qps gave p99 5.9 ms, 19,524 gave 6.5 ms, 16,270 gave 0.69 ms), as in the 2026-11-22 runs. The server's dnsdist configuration at this run had one UDP listener (`reusePort` absent), which is the default; the tuning knobs of #18 were not measured. A same-host run on 2026-11-22 reached about 34,000 qps, so the two-node limit of about 19,000 qps may come from how the single listener handles the packet rate, not from the cache or the Filter. That is a hypothesis to test with the udp-listeners knob, one knob at a time.

### Technitium 15.6.2 (full Filter, 10,218,839 names): no result

Technitium loaded the whole Filter (about 3.6 GiB resident afterwards) and passed the harness checks, but under the harness load it lost about half of all queries:

- The warm-up at 2000 qps did not finish in more than 25 minutes (PowerSVX finishes it in about a minute). Technitium reported thousands of queries as dropped, and the kernel counted UDP receive buffer errors on the server.
- After that, fixed-rate runs from 100 to 1000 qps over the same names lost 49-53% of the queries on every pass, for every type (A, AAAA, HTTPS), and the answered ones came back in about 0.3 ms.
- After restarting the container, 600 names at 100 qps were answered 100%, twice.
- A second attempt with a 200 qps warm-up again dropped tens of thousands of queries (the dashboard's dropped counter) and had not finished its warm-up after 20 minutes. It was stopped.

These facts do not say whether this is how Technitium behaves under cold load with its default resolver settings, or something about this setup (the allow list, the client count, the network path). The comparison must not be quoted until that is separated. Next step: run Technitium with a lower client count and a long, low-rate warm-up, watch its own counters while it runs, and try the same on a second host.
