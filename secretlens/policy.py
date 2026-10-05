"""Exact, explicit, expiring approvals; not a blanket ignore mechanism."""
from __future__ import annotations
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from .core import RULES, ScanError


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ScanError("Approval policy contains duplicate keys")
        result[key] = value
    return result


def _invalid_literal(value):
    raise ScanError("Approval policy contains a nonfinite literal")


def load_policy(path: Path):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ScanError("Approval policy must be a regular file at most 1 MiB")
        with path.open("rb") as stream:
            content = stream.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ScanError("Approval policy exceeds limit")
        return json.loads(content.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_invalid_literal)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ScanError("Cannot read valid approval policy") from exc


def apply_policy(report, policy, *, now=None):
    """Keep all detections visible; gate only explicitly approved candidates.

    Review fields are audit metadata, not a signature or authenticated identity.
    The caller chooses a trusted policy separately from the scanned repository.
    """
    now = now or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ScanError("Approval clock must be timezone-aware")
    if not isinstance(policy, dict) or set(policy) != {"version", "approvals"} or type(policy["version"]) is not int or policy["version"] != 1:
        raise ScanError("Unsupported approval policy")
    entries = policy["approvals"]
    if not isinstance(entries, list) or len(entries) > 1000:
        raise ScanError("Approval policy must contain at most 1000 exact entries")
    rules = {rule for rule, _, _ in RULES} - {"private-key"}
    approvals = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "rule", "fingerprint", "reviewer", "reason", "expires_at"}:
            raise ScanError("Malformed exact approval entry")
        path = entry["path"]
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or any(
            part in ("", ".", "..") for part in path.split("/")
        ) or any(char in path for char in "*?[]\x00") or re.match(r"^[A-Za-z]:", path):
            raise ScanError("Approval must name one exact relative path, not a glob")
        if not isinstance(entry["rule"], str) or entry["rule"] not in rules:
            raise ScanError("Unknown or non-approvable rule; private keys cannot be approved")
        if not isinstance(entry["fingerprint"], str) or not re.fullmatch(r"[a-f0-9]{64}", entry["fingerprint"]):
            raise ScanError("Approval needs an exact SHA256 fingerprint")
        if any(not isinstance(entry[key], str) or not 1 <= len(entry[key].strip()) <= 200 for key in ("reviewer", "reason")):
            raise ScanError("Approval requires bounded nonempty reviewer and reason")
        try:
            expiration = datetime.fromisoformat(entry["expires_at"])
        except (ValueError, TypeError) as exc:
            raise ScanError("Approval expiry must be an ISO8601 timestamp") from exc
        if expiration.tzinfo is None or not now < expiration <= now + timedelta(days=90):
            raise ScanError("Approval expired or exceeds 90-day renewal window")
        key = (path, entry["rule"], entry["fingerprint"])
        if key in approvals:
            raise ScanError("Duplicate exact approval")
        approvals[key] = entry
    result = copy.deepcopy(report)
    approved, used = 0, set()
    for finding in result["findings"]:
        key = (finding["path"], finding["rule"], finding["fingerprint"])
        entry = approvals.get(key)
        finding["approved"] = entry is not None
        if entry is not None:
            approved += 1
            used.add(key)
            finding["approval"] = {name: entry[name] for name in ("reviewer", "reason", "expires_at")}
    result["policy"] = {"approved_findings": approved,
                        "unapproved_findings": len(result["findings"]) - approved,
                        "unused_approvals": len(approvals) - len(used)}
    result["clean"] = len(result["findings"]) == approved
    return result
