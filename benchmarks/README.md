# Synthetic index scale evidence

## Repeated dense-blob comparison (v0.5.1)

Run `python -m benchmarks.density` from the repository root. Only generated in-memory Unicode text is inspected; no actual repository or user files. The independent reference keeps the former whole-prefix line/column counting, while the current scanner advances segments per rule. Both results must match exactly. One untimed warmup for each, three samples per size, alternating execution order; Python3.12.10/Windows with tracemalloc. Reference starts from decoded text; scanner includes UTF8 decode and budget checks, so this is not an isolated location-only microbenchmark. Regex/hash/sort work remains; do not generalize these numbers to complete index throughput.

Recorded second local run2026-10-07 (all seconds; first run also passed but was not fully retained):

| candidates / bytes | prefix reference samples | segmented samples | median reference / segmented |
|---|---|---|---|
| 1000 / 48000 | .024234, .025117, .023115 | .016097, .017301, .015926 | .024234 / .016097 |
| 5000 / 240000 | .364934, .380462, .375767 | .084622, .086565, .084370 | .375767 / .084622 |
| 10000 / 480000 | 1.352234, 1.320581, 1.329831 | .175312, .177378, .174734 | 1.329831 / .175312 |

Python allocation peak bytes for reference/current respectively:1000 max323640/411623;5000 max1896664/2336647;10000 max3945096/4824943. Current includes decoded text: memory is not claimed reduced. Setup/retained expected oracle/nativeRSS/GitIO are excluded. No CI timing threshold, production SLA or universal acceleration claim. A deterministic operation-count regression also checks that candidate positions do not rescan prior prefixes. Default10,000 occurrences is a bounded-report guard, not a process resource sandbox.

`python benchmarks/scale.py` creates its own temporary Git repository with10,000 unique clean text blobs, stages them and asserts full coverage. It never reads a real user repository. Setup and file creation are excluded from scan timing.

Windows/Python3.12 measurement on2026-10-06 with tracemalloc enabled:10,000 files,268,890 indexed bytes,5.527 seconds,3 Git processes, Python allocation peak4,156,107 bytes. One sample only; filesystem caches/hardware/tracemalloc affect results. This is not total process RSS: Git memory is not included. No timing threshold is enforced in CI and no causal speedup multiplier is claimed.

The previous implementation launched81 Git commands for40 unique blobs (one listing plus per-object size/read); the regression reproduced this before optimization. The new implementation uses one listing, one batch size preflight and one streaming batch process for nonempty indexes. It still scans duplicate contents separately for each path, so findings/approvals remain path-scoped. Every streamed blob is checked against its pinned Git object ID; no cross-file credential cache is retained.
