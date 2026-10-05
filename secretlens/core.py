"""Scan immutable Git blobs, never report their contents."""
from __future__ import annotations

import hashlib
from contextlib import closing
import os
from pathlib import Path
import re
import subprocess
import threading

BATCH_TIMEOUT_SECONDS = 30


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


def _git_env():
    # Do not silently substitute replace refs or fetch absent promisor objects.
    return {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1"}


def _git(repository: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(["git", "-C", str(repository), *args],
                                capture_output=True, input=input_bytes,
                                env=_git_env(), timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        # Never echo Git stderr: filenames/configuration may contain sensitive data.
        raise ScanError("Git unavailable or timed out") from exc
    if result.returncode:
        raise ScanError("Git failed; check repository integrity and index conflicts")
    return result.stdout


def _object_header(header: bytes, expected_id: str) -> int:
    parts = header.rstrip(b"\n").split(b" ")
    if (not header.endswith(b"\n") or len(parts) != 3
            or parts[0] != expected_id.encode("ascii") or parts[1] != b"blob"
            or not re.fullmatch(rb"(?:0|[1-9][0-9]*)", parts[2])):
        raise ScanError("Malformed or missing Git blob header")
    try:
        return int(parts[2])
    except ValueError as exc:
        raise ScanError("Malformed Git blob size") from exc


def _read_exact(stream, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        data = stream.read(remaining)
        if not data or len(data) > remaining:
            raise ScanError("Truncated Git blob response")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def _batch_blobs(repository: Path, entries: list, sizes: dict):
    """One request at a time avoids pipe deadlock and bounds retained blob data.

    A watchdog kills a stalled process even while stdout.read blocks on Windows.
    Consumers must close the iterator if scanning raises before exhaustion.
    """
    try:
        process = subprocess.Popen(["git", "-C", str(repository), "cat-file", "--batch"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=_git_env())
    except OSError as exc:
        raise ScanError("Git batch process unavailable") from exc
    expired = threading.Event()
    def timeout():
        expired.set()
        try:
            process.kill()
        except OSError:
            pass
    timer = threading.Timer(BATCH_TIMEOUT_SECONDS, timeout)
    timer.daemon = True
    timer.start()
    try:
        for path, object_id in entries:
            process.stdin.write(object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            size = _object_header(process.stdout.readline(200), object_id)
            if size != sizes[object_id]:
                raise ScanError("Git object size mismatch")
            blob = _read_exact(process.stdout, size)
            if process.stdout.read(1) != b"\n":
                raise ScanError("Malformed Git blob terminator")
            algorithm = "sha1" if len(object_id) == 40 else "sha256"
            hasher = hashlib.new(algorithm, usedforsecurity=False)
            hasher.update(f"blob {size}\0".encode("ascii"))
            hasher.update(blob)
            if hasher.hexdigest() != object_id:
                raise ScanError("Git blob content does not match pinned object ID")
            yield path, blob
            del blob
        process.stdin.close()
        if process.stdout.read(1):
            raise ScanError("Unexpected trailing Git batch data")
        if process.wait(timeout=BATCH_TIMEOUT_SECONDS) or expired.is_set():
            raise ScanError("Git batch failed or timed out")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError("Git batch failed or timed out") from exc
    finally:
        timer.cancel()
        timer.join()
        if process.poll() is None:
            process.kill()
        process.wait()
        if not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass  # A broken pipe during cleanup must not leak raw errors.
        process.stdout.close()


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
    object_ids = list(dict.fromkeys(object_id for _, object_id in entries))
    if object_ids:
        headers = _git(repository, "cat-file", "--batch-check",
                       input_bytes=("\n".join(object_ids) + "\n").encode("ascii")).splitlines(keepends=True)
        if len(headers) != len(object_ids):
            raise ScanError("Git batch size response count mismatch")
        for object_id, header in zip(object_ids, headers):
            size = _object_header(header, object_id)
            if size > max_blob_bytes:
                raise ScanError("Blob exceeds scan limit; coverage is incomplete")
            sizes[object_id] = size
    for _, object_id in entries:
        total += sizes[object_id]
        if total > max_total_bytes:
            raise ScanError("Total indexed bytes exceed scan limit; coverage is incomplete")
    findings = []
    # No cache of secrets across paths. Empty indexes need no blob process.
    if entries:
        with closing(_batch_blobs(repository, entries, sizes)) as blobs:
            for path, blob in blobs:
                findings.extend(scan_blob(path, blob))
                del blob
    return {"version": 1, "scope": "entire-git-index", "complete": True,
            "clean": not findings, "files_scanned": len(entries),
            "bytes_scanned": total, "index_sha256": hashlib.sha256(index).hexdigest(),
            "findings": findings}
