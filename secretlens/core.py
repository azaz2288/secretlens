"""Scan immutable Git blobs, never report their contents."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess


class ScanError(Exception):
    """A scan cannot safely establish its result."""


# No network validation: matches are candidates, not proven active credentials.
RULES = (
    ("github-token", re.compile(r"(?<![\w])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})(?![\w])"), 0),
    ("aws-access-id", re.compile(r"(?<![\w])(?:AKIA|ASIA)[A-Z0-9]{16}(?![\w])"), 0),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), 0),
    ("assigned-secret", re.compile(
        r'''(?i)["']?\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret[_-]?key)["']?\s*[:=]\s*(["'])([^"'\r\n]{16,512})\1'''), 2),
)


def _git(repository: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(["git", "-C", str(repository), *args],
                                capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        # Never echo Git stderr: filenames/configuration may contain sensitive data.
        raise ScanError("Git unavailable or timed out") from exc
    if result.returncode:
        raise ScanError("Git failed; check repository integrity and index conflicts")
    return result.stdout


def _text(blob: bytes) -> str:
    # BOM-aware wide encodings; otherwise inspect ASCII-compatible sequences even
    # inside binary blobs instead of silently skipping images/archives.
    if blob.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encoding = "utf-32"
    elif blob.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    else:
        encoding = "utf-8-sig"
    return blob.decode(encoding, errors="replace")


def scan_blob(path: str, blob: bytes) -> list[dict]:
    """Metadata only; never include snippets or matched credentials."""
    content = _text(blob)
    findings = []
    for rule, pattern, group in RULES:
        for match in pattern.finditer(content):
            start = match.start(group)
            value = match.group(group)
            fingerprint = hashlib.sha256(
                path.encode("utf-8", errors="surrogateescape") + b"\x00" +
                rule.encode("ascii") + b"\x00" + value.encode("utf-8")
            ).hexdigest()
            findings.append({"path": path, "rule": rule,
                             "line": content.count("\n", 0, start) + 1,
                             "column": start - content.rfind("\n", 0, start),
                             "fingerprint": fingerprint})
    return sorted(findings, key=lambda item: (item["line"], item["column"], item["rule"]))


def scan_index(repository: Path, *, max_blob_bytes: int = 1024 * 1024,
               max_total_bytes: int = 32 * 1024 * 1024,
               max_files: int = 10000) -> dict:
    """Inspect every file in the index, including unchanged tracked files.

    Object IDs from one index listing pin the input. No worktree file is read.
    Limits fail closed, before any blob is read. Symlinks/submodules are rejected.
    """
    if any(type(value) is not int or value < 1 for value in
           (max_blob_bytes, max_total_bytes, max_files)):
        raise ScanError("Scan limits must be positive integers")
    index = _git(repository, "ls-files", "--stage", "-z")
    entries = []
    for entry in index.split(b"\x00"):
        if not entry:
            continue
        try:
            metadata, raw_path = entry.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ")
        except ValueError as exc:
            raise ScanError("Malformed Git index listing") from exc
        if stage != b"0":
            raise ScanError("Unmerged index; resolve conflicts before scanning")
        if mode not in (b"100644", b"100755"):
            raise ScanError("Index contains a symlink or submodule; coverage is incomplete")
        if not re.fullmatch(rb"(?:[a-f0-9]{40}|[a-f0-9]{64})", object_id):
            raise ScanError("Malformed Git object ID")
        entries.append((raw_path.decode("utf-8", errors="surrogateescape"), object_id.decode("ascii")))
    if len(entries) > max_files:
        raise ScanError("File count exceeds scan limit; coverage is incomplete")
    sizes = {}
    total = 0
    for _, object_id in entries:
        if object_id not in sizes:
            try:
                size = int(_git(repository, "cat-file", "-s", object_id))
            except ValueError as exc:
                raise ScanError("Malformed Git blob size") from exc
            if size < 0 or size > max_blob_bytes:
                raise ScanError("Blob exceeds scan limit; coverage is incomplete")
            sizes[object_id] = size
        total += sizes[object_id]
        if total > max_total_bytes:
            raise ScanError("Total indexed bytes exceed scan limit; coverage is incomplete")
    findings = []
    # Cache decoded matches per object would retain secrets unnecessarily. Read
    # at most one bounded blob at a time, even when multiple paths share it.
    for path, object_id in entries:
        blob = _git(repository, "cat-file", "blob", object_id)
        if len(blob) != sizes[object_id]:
            raise ScanError("Git object size mismatch")
        findings.extend(scan_blob(path, blob))
    return {"version": 1, "scope": "entire-git-index", "complete": True,
            "clean": not findings, "files_scanned": len(entries),
            "bytes_scanned": total, "index_sha256": hashlib.sha256(index).hexdigest(),
            "findings": findings}
