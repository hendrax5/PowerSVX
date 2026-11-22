# Preliminary lab runs, 2026-11-22

These are not a Baseline. No Technitium run exists yet, and the server details in these files are empty because the runs did not use ssh to reach the server.

Server under test: one lab node, 12 vCPU (Xeon E5-2680 v4, KVM), 8 GB, stock generated dnsdist and Unbound configuration, nothing else changed. Query set: 500,000 lines, SHA-256 prefix `3913803e7e0422e0`, built from the Tranco top 10,000 and a 1-in-300 sample of the Filter feed.

| File | Load generator | Highest rate within loss <= 0.1% and p99 <= 5 ms | Note |
|---|---|---|---|
| `smoke-samehost-...121454Z.json` | same host as the server | about 34,000 qps | one dnsdist thread at about 70% of a core, the others idle |
| `twonode-stock-...124935Z.json` | second node, 0.1 ms away | about 18,600 qps | the p99 per step is not monotonic: 15.7k qps gave 4.2 ms, 19.6k gave 5.1 ms, 31k gave 8.2 ms |

Two further fixed-rate runs from the second node at 25,000 qps answered about 24,700-24,800 qps with p99 7.3 ms and 4.6 ms and loss of about 0.02%.

Read the maximum as "somewhere between 15,000 and 30,000 qps depending on the p99 criterion", not as a sharp limit. p99 sits near the 5 ms threshold over that whole range and varies run to run, so a single 20-second step cannot place the limit precisely. A publishable number needs longer steps and repeated runs.
