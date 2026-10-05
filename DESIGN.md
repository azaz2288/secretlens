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
2. **Hook integration:** opt-in installation that preserves existing hooks, supports environment discovery and clean uninstallation. Recheck the index snapshot and document concurrent staging limitations.
3. **Rule evaluation:** synthetic positive/negative corpus, per-rule precision/recall evidence, encoding/escaped-text tests. Do not make a universal detection claim.
4. **Scale follow-up:** distribution/repeated-run benchmarks, larger synthetic binary blobs, worst-case candidate-density evaluation and findings limits. Basic10,000-file batch retrieval, timeout and corrupt-protocol tests are implemented; scanner resource isolation is not.
5. **Release:** cross-platform CI, installed wheel smoke check, migration policy for report versions and reproducible distribution checks.

## Non-goals
Credential validity probing, automatic rotation, history rewriting, editing another project's source, or OS-level sandboxing. This is defense in depth, not proof of repository secrecy.
