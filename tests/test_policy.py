import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import io
from secretlens.core import ScanError, scan_blob
from secretlens.policy import apply_policy, load_policy
from secretlens.__main__ import main

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)


def report():
    candidate = ("gh" + "p_" + "A1b2" * 9).encode()
    return {"version": 1, "complete": True, "clean": False,
            "findings": scan_blob("tests/fixture.txt", candidate)}


def policy(value):
    finding = value["findings"][0]
    return {"version": 1, "approvals": [{key: finding[key] for key in ("path", "rule", "fingerprint")} |
            {"reviewer": "test-reviewer", "reason": "Synthetic invalid fixture, reviewed", "expires_at": (NOW + timedelta(days=7)).isoformat()}]}


class PolicyTests(unittest.TestCase):
    def test_exact_approval_keeps_detection_and_does_not_mutate_original(self):
        original = report()
        before = copy.deepcopy(original)
        result = apply_policy(original, policy(original), now=NOW)
        self.assertTrue(result["clean"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertTrue(result["findings"][0]["approved"])
        self.assertEqual(result["policy"]["approved_findings"], 1)
        self.assertEqual(original, before)

    def test_moved_or_changed_candidate_cannot_inherit_approval(self):
        original = report()
        for key, value in (("path", "other.txt"), ("fingerprint", "0" * 64), ("rule", "aws-access-id")):
            changed = copy.deepcopy(original)
            changed["findings"][0][key] = value
            with self.subTest(key=key):
                result = apply_policy(changed, policy(original), now=NOW)
                self.assertFalse(result["clean"])
                self.assertEqual(result["policy"]["unused_approvals"], 1)

    def test_expiry_boundary_and_renewal_limit(self):
        original = report()
        for expiry in (NOW, NOW - timedelta(seconds=1), NOW + timedelta(days=90, seconds=1)):
            candidate = policy(original)
            candidate["approvals"][0]["expires_at"] = expiry.isoformat()
            with self.subTest(expiry=expiry), self.assertRaises(ScanError):
                apply_policy(original, candidate, now=NOW)
        candidate = policy(original)
        candidate["approvals"][0]["expires_at"] = (NOW + timedelta(days=90)).isoformat()
        self.assertTrue(apply_policy(original, candidate, now=NOW)["clean"])

    def test_naive_and_invalid_expiry_rejected(self):
        original = report()
        for expiry in ("2026-10-07", "not-a-date", None, 1):
            candidate = policy(original)
            candidate["approvals"][0]["expires_at"] = expiry
            with self.subTest(expiry=expiry), self.assertRaises(ScanError):
                apply_policy(original, candidate, now=NOW)

    def test_globs_absolute_and_traversal_paths_rejected(self):
        original = report()
        for path in ("*", "tests/**", "tests/[abc]", "../outside", "/absolute", "C:/absolute", "a\\b", "a//b"):
            candidate = policy(original)
            candidate["approvals"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(ScanError):
                apply_policy(original, candidate, now=NOW)

    def test_private_key_not_approvable(self):
        original = report()
        candidate = policy(original)
        candidate["approvals"][0]["rule"] = "private-key"
        with self.assertRaisesRegex(ScanError, "private keys"):
            apply_policy(original, candidate, now=NOW)

    def test_blank_review_metadata_and_duplicates_rejected(self):
        original = report()
        for field in ("reason", "reviewer"):
            candidate = policy(original)
            candidate["approvals"][0][field] = "   "
            with self.assertRaises(ScanError):
                apply_policy(original, candidate, now=NOW)
        candidate = policy(original)
        candidate["approvals"] *= 2
        with self.assertRaises(ScanError):
            apply_policy(original, candidate, now=NOW)

    def test_empty_policy_never_hides_candidates(self):
        result = apply_policy(report(), {"version": 1, "approvals": []}, now=NOW)
        self.assertFalse(result["clean"])
        self.assertEqual(result["policy"]["unapproved_findings"], 1)

    def test_malformed_policy_and_unknown_fields_fail_closed(self):
        for candidate in ({"version": True, "approvals": []}, {"version": 1, "approvals": [], "ignore": "*"},
                          {"version": 1, "approvals": "all"}, {"version": 1, "approvals": [{}]}):
            with self.subTest(candidate=candidate), self.assertRaises(ScanError):
                apply_policy(report(), candidate, now=NOW)

    def test_duplicate_json_and_nonfinite_literals_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            for content in ('{"version":0,"version":1,"approvals":[]}', '{"version":1,"approvals":[],"x":NaN}'):
                path.write_text(content)
                with self.assertRaises(ScanError):
                    load_policy(path)
            path.write_text(json.dumps(policy(report())))
            self.assertTrue(apply_policy(report(), load_policy(path), now=NOW)["clean"])

    def test_unhashable_rule_and_fingerprint_fail_closed(self):
        for field in ("rule", "fingerprint"):
            candidate = policy(report())
            candidate["approvals"][0][field] = ["bad"]
            with self.assertRaises(ScanError):
                apply_policy(report(), candidate, now=NOW)

    def test_cli_explicit_policy_gate_and_expired_policy_code(self):
        original = report()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            candidate = policy(original)
            candidate["approvals"][0]["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
            path.write_text(json.dumps(candidate), encoding="utf-8")
            captured = io.StringIO()
            with patch("secretlens.__main__.scan_index", return_value=original), contextlib.redirect_stdout(captured):
                code = main(["--approvals", str(path)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(captured.getvalue())["policy"]["approved_findings"], 1)
            candidate["approvals"][0]["expires_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
            path.write_text(json.dumps(candidate), encoding="utf-8")
            captured = io.StringIO()
            with patch("secretlens.__main__.scan_index", return_value=original), contextlib.redirect_stdout(captured):
                code = main(["--approvals", str(path)])
            self.assertEqual(code, 2)
            self.assertFalse(json.loads(captured.getvalue())["complete"])


if __name__ == "__main__":
    unittest.main()
