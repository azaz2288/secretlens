# Engineering plan and acceptance criteria

## Problem
Working-tree scanners can miss a credential which remains staged after the user edits it away. SecretLens must inspect the exact index object set without disclosing the candidate value or sending it to an external service.

## v0.1 implemented boundary
Index listing pins immutable object IDs. Preflight rejects conflicts, nonregular modes and declared-size/file-count limits; accepted blobs are read one at a time. BOM-aware decoding and bounded candidate rules return metadata-only findings. CLI returns complete/clean separately, with 0/1/2 exit codes. User filenames and deterministic fingerprints remain sensitive metadata.

## v0.2 completed milestone
Exact path+rule+fingerprint approvals with mandatory reviewer/reason, timezone-aware expiry and maximum 90-day renewal horizon. Explicit trusted policy loading only; no auto-loaded repository ignore file. Private-key approvals denied. Findings stay visible, unused approvals reported, moved/changed candidates cannot inherit approval. Policy identity is metadata, not authenticated approval or signature.

## Subsequent milestones (not completed)

v0.3 scale slice completed: three Git processes independent of index count, all-size preflight before content, streaming one request at a time with protocol/object-hash validation, replace refs/lazy fetch disabled and a watchdog. Synthetic10,000-file measurement is recorded in benchmarks/README.md. This is bounded retained blob data, not an OS sandbox or a worst-case scanner CPU guarantee.
1. **Approval hardening:** signed policy distribution and independently authenticated review workflow, without treating a review string as identity proof.
2. **Hook follow-up:** v0.4 opt-in normal-repository install/unchanged-generated-hook removal, explicit isolated installed runtime and existing/shared-hook refusal are implemented. Git partial-commit temporary indexes are retained, repository Python shadowing rejected by -I. Environment relocation, portable managed hook chains and atomic staging-to-commit binding remain unimplemented; no automatic coverage reduction.
3. **Rule evaluation:** v0.5 deterministic647-sample synthetic corpus and independent truth,625 supported/22 known-gap cohorts, per-rule sample-presence confusion counts plus exact occurrence/location checks, digest-bound redacted report and installed CLI are implemented. Unbiased real-world corpus, larger provider coverage and escaped/wide-without-BOM detection are not; known misses/false positives remain in overall denominators. Do not make a universal detection claim.
4. **Scale follow-up:** distribution/repeated-run benchmarks, larger synthetic binary blobs, worst-case candidate-density evaluation and findings limits. Basic10,000-file batch retrieval, timeout and corrupt-protocol tests are implemented; scanner resource isolation is not.
5. **Release:** cross-platform CI, installed wheel smoke check, migration policy for report versions and reproducible distribution checks.

## Non-goals
Credential validity probing, automatic rotation, history rewriting, editing another project's source, or OS-level sandboxing. This is defense in depth, not proof of repository secrecy.
