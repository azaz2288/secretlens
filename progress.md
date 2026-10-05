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
