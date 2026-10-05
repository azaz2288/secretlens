# Synthetic index scale evidence

`python benchmarks/scale.py` creates its own temporary Git repository with10,000 unique clean text blobs, stages them and asserts full coverage. It never reads a real user repository. Setup and file creation are excluded from scan timing.

Windows/Python3.12 measurement on2026-10-06 with tracemalloc enabled:10,000 files,268,890 indexed bytes,5.527 seconds,3 Git processes, Python allocation peak4,156,107 bytes. One sample only; filesystem caches/hardware/tracemalloc affect results. This is not total process RSS: Git memory is not included. No timing threshold is enforced in CI and no causal speedup multiplier is claimed.

The previous implementation launched81 Git commands for40 unique blobs (one listing plus per-object size/read); the regression reproduced this before optimization. The new implementation uses one listing, one batch size preflight and one streaming batch process for nonempty indexes. It still scans duplicate contents separately for each path, so findings/approvals remain path-scoped. Every streamed blob is checked against its pinned Git object ID; no cross-file credential cache is retained.
