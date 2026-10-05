# Verified engineering record

## 2026-10-06 — initial usable slice, not flagship completion
- Implemented read-only full-index scanning with immutable blob IDs, secret-free reports and fail-closed limits.
- 24 unittest cases: 23 passed on Windows, one POSIX filename case skipped because Windows forbids tab/newline names. Linux CI must run that case before claiming cross-platform verification.
- Cases cover worktree/index divergence, committed unchanged files, deleted files/history scope, index mutation during scanning, encodings, binary token inspection, size limits, conflict stages, symlink/submodule modes, exact snapshot digest and CLI exit codes.
- compileall passed; built secretlens-0.1.0-py3-none-any.whl. Distribution smoke test and remote CI are separate verification steps.
- First self-scan correctly detected a synthetic long password fixture embedded in source. Reassembled fixture at runtime rather than creating a blanket exception. No actual credentials were included.
- Follow-up engineering milestones are in DESIGN.md; no claim that all planned features are implemented.

## 2026-10-06 — v0.2 precise approval milestone
- Implemented explicit trusted policy, exact path/rule/fingerprint, required review metadata, timezone-aware expiry and 90-day limit; private keys cannot be approved.
- Rejected malformed/duplicate/blanket/expired policies; approval never removes findings, moving/changing token cannot inherit it.
- Added policy and CLI expiry tests. Reviewer text is explicitly not authenticated identity; no signature or full multi-party approval claim.

## 2026-10-06 — v0.3 batch-object milestone
- Before implementation,40 unique blobs launched81 Git commands; replace refs could hide a pinned indexed token. Both new regressions failed, then passed after fixes.
- Batched size preflight, streamed content requests, strict framing and Git object hash verification;3 processes for nonempty indexes. Disabled replace refs/lazy fetch. Watchdog test kills a real stalled Python child, and failure paths close process pipes.
-44 tests: Windows43 passed/1 POSIX filename skipped. Added SHA256 Git repository, duplicate path-scoped findings, short reads/truncation, malformed header/type/length/terminator/hash/trailing data, and replacement-ref regressions.
-10,000-file synthetic benchmark:5.527s,3 Git processes,4,156,107 bytes Python allocation peak; native Git RSS and setup excluded. Exact limits in benchmarks/README.md; not a universal speed claim.

## 2026-10-06 — v0.4 explicit pre-commit gate
- Implemented explicit install/uninstall for a regular top-level Git repository, exclusive publish, existing/shared/external hook refusal, current-version installed runtime verification and isolated Python invocation. Never auto-install in portfolio repositories. Exact approvals and positive scan limits may be bound explicitly.
- Real synthetic Git commits demonstrate staged secret detection after worktree cleanup, non-disclosing rejection, runtime/PYTHONPATH shadow protection, partial-commit temporary-index correctness and unavailable runtime/coverage failure blocking. Uninstall preserves user-modified scripts and unrelated hooks; no history/config/index mutation.
- New API initially unavailable; first 15 hook tests had one uninstall error because stat comparison included read-updated atime. Replaced with identity/mode/size/mtime/ctime fingerprint, retained byte-for-byte managed-hook verification. Git test output decoded explicitly as UTF-8 after a Windows GBK reader-thread exception in missing-runtime diagnostics. Subsequent 59-test suite passed with two Windows skips; additional junction/bare/invalid-policy boundaries added before final verification.
- Hook is bypassable with --no-verify or privileged edits, and cannot bind concurrent staging atomically. It is not a substitute for protected CI, signed policy or OS isolation. Independent wheel/installed CLI/current-SHA CI are separate evidence.
- Final local suite: 62 tests, Windows 60 passed and two skips (privileged hook symlink creation and POSIX tab/newline filenames); real Windows hooks-directory junction refusal passed. Built secretlens-0.4.0-py3-none-any.whl, SHA256 1bf2a6dfdd11da098dfbfe10d20c321a0e976495e1d369645c12ab6874e5045c, installed into the project-specific virtual environment, and verified version/site-packages from outside the source tree. Installed isolated hook_demo passed clean commit, non-disclosing staged-candidate rejection, preserved HEAD and unchanged index after managed-hook removal; pip check passed. Current-SHA CI after push remains a separate cross-platform gate.
