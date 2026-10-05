import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from secretlens.core import ScanError, scan_blob, scan_index


def token():
    # Synthetic test token, assembled to avoid committing a token-shaped string.
    return "gh" + "p_" + "A1b2" * 9


class BlobTests(unittest.TestCase):
    def test_github_token_redacted_and_located(self):
        secret = token()
        results = scan_blob("safe.txt", ("header\nxx " + secret + "\n").encode())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule"], "github-token")
        self.assertEqual((results[0]["line"], results[0]["column"]), (2, 4))
        self.assertNotIn(secret, json.dumps(results))
        self.assertEqual(len(results[0]["fingerprint"]), 64)

    def test_aws_private_key_and_assignment_candidates(self):
        samples = [
            ("AK" + "IA" + "B" * 16, "aws-access-id"),
            ("-----BEGIN " + "RSA PRIVATE KEY-----", "private-key"),
            ('"api_key": "' + "testing-only-long-value" + '"', "assigned-secret"),
        ]
        for content, rule in samples:
            with self.subTest(rule=rule):
                result = scan_blob("config", content.encode())
                self.assertEqual(result[0]["rule"], rule)
                self.assertNotIn(content, json.dumps(result))

    def test_assignment_column_is_secret_start(self):
        content = "password = " + json.dumps("this-is-a-test-value")
        result = scan_blob("config", content.encode())[0]
        self.assertEqual(result["column"], content.index("this") + 1)

    def test_utf_encodings_with_bom(self):
        for encoding in ("utf-8-sig", "utf-16", "utf-32"):
            with self.subTest(encoding=encoding):
                result = scan_blob("config", ("备注\n" + token()).encode(encoding))
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["line"], 2)

    def test_utf16_utf32_big_endian_bom(self):
        for bom, encoding in ((b"\xfe\xff", "utf-16-be"), (b"\x00\x00\xfe\xff", "utf-32-be")):
            with self.subTest(encoding=encoding):
                self.assertEqual(len(scan_blob("config", bom + token().encode(encoding))), 1)

    def test_binary_ascii_token_not_skipped(self):
        self.assertEqual(len(scan_blob("asset.bin", b"\xff\x00" + token().encode() + b"\x00")), 1)

    def test_clean_and_short_values(self):
        self.assertEqual(scan_blob("readme", b"normal documentation\npassword = 'short'"), [])

    def test_fingerprint_stable_and_path_scoped(self):
        first = scan_blob("one", token().encode())[0]["fingerprint"]
        self.assertEqual(first, scan_blob("one", token().encode())[0]["fingerprint"])
        self.assertNotEqual(first, scan_blob("two", token().encode())[0]["fingerprint"])


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Synthetic Test")
        self.git("config", "user.email", "test@example.invalid")

    def git(self, *args, input=None):
        result = subprocess.run(["git", "-C", str(self.root), *args],
                                input=input, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result.stdout

    def stage(self, name, content):
        (self.root / name).write_bytes(content)
        self.git("add", "--", name)

    def test_empty_index_is_complete(self):
        report = scan_index(self.root)
        self.assertTrue(report["clean"])
        self.assertTrue(report["complete"])
        self.assertEqual(report["files_scanned"], 0)

    def test_staged_secret_found_even_if_worktree_cleaned(self):
        self.stage("配置 file.txt", token().encode())
        (self.root / "配置 file.txt").write_text("clean", encoding="utf-8")
        report = scan_index(self.root)
        self.assertFalse(report["clean"])
        self.assertEqual(report["findings"][0]["path"], "配置 file.txt")
        self.assertNotIn(token(), json.dumps(report))

    def test_unstaged_secret_not_part_of_scan(self):
        self.stage("clean", b"safe")
        (self.root / "clean").write_text(token(), encoding="utf-8")
        (self.root / "untracked").write_text(token(), encoding="utf-8")
        self.assertTrue(scan_index(self.root)["clean"])

    def test_committed_unchanged_index_is_still_scanned(self):
        self.stage("secret", token().encode())
        self.git("commit", "-qm", "synthetic fixture")
        self.assertFalse(scan_index(self.root)["clean"])

    def test_deleted_file_and_history_are_not_scanned(self):
        self.stage("secret", token().encode())
        self.git("commit", "-qm", "synthetic fixture")
        self.git("rm", "--", "secret")
        self.assertTrue(scan_index(self.root)["clean"])

    def test_snapshot_ids_pin_contents_if_index_changes_during_scan(self):
        self.stage("changing", token().encode())
        import secretlens.core as core
        original_git = core._git

        def mutate_after_listing(repository, *args):
            output = original_git(repository, *args)
            if args[0] == "ls-files":
                self.stage("changing", b"clean")
            return output

        with patch.object(core, "_git", side_effect=mutate_after_listing):
            report = scan_index(self.root)
        self.assertFalse(report["clean"])
        self.assertTrue(scan_index(self.root)["clean"])

    @unittest.skipIf(os.name == "nt", "Windows filenames cannot contain tab/newline")
    def test_tab_and_newline_filename(self):
        name = "line\nwith\ttabs"
        self.stage(name, token().encode())
        report = scan_index(self.root)
        self.assertEqual(report["findings"][0]["path"], name)
        encoded = json.dumps(report, ensure_ascii=True)
        self.assertEqual(json.loads(encoded)["findings"][0]["path"], name)

    def test_size_limits_fail_closed(self):
        self.stage("large", b"x" * 20)
        with self.assertRaisesRegex(ScanError, "Blob exceeds"):
            scan_index(self.root, max_blob_bytes=19)
        self.assertTrue(scan_index(self.root, max_blob_bytes=20)["clean"])

    def test_total_and_file_limits(self):
        self.stage("a", b"abc")
        self.stage("b", b"abc")
        with self.assertRaisesRegex(ScanError, "Total indexed"):
            scan_index(self.root, max_total_bytes=5)
        self.assertEqual(scan_index(self.root, max_total_bytes=6)["bytes_scanned"], 6)
        with self.assertRaisesRegex(ScanError, "File count"):
            scan_index(self.root, max_files=1)

    def test_limits_checked_before_reading_any_blob(self):
        self.stage("a", token().encode())
        self.stage("z", b"x" * 100)
        with patch("secretlens.core.scan_blob") as scanner:
            with self.assertRaises(ScanError):
                scan_index(self.root, max_blob_bytes=50)
        scanner.assert_not_called()

    def test_nonregular_modes_fail_closed_without_following_targets(self):
        self.stage("mode", b"safe")
        object_id = self.git("rev-parse", ":mode").strip().decode()
        for mode in ("120000", "160000"):
            with self.subTest(mode=mode):
                self.git("update-index", "--cacheinfo", mode, object_id, "mode")
                with self.assertRaisesRegex(ScanError, "symlink or submodule"):
                    scan_index(self.root)

    def test_unmerged_index_fails_closed(self):
        self.stage("conflict", b"safe")
        object_id = self.git("rev-parse", ":conflict").strip().decode()
        self.git("update-index", "--force-remove", "conflict")
        self.git("update-index", "--index-info", input=f"100644 {object_id} 1\tconflict\n".encode())
        with self.assertRaisesRegex(ScanError, "Unmerged"):
            scan_index(self.root)

    def test_invalid_limits(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ScanError):
                scan_index(self.root, max_files=value)

    def test_report_binds_index_listing(self):
        self.stage("clean", b"safe")
        self.assertEqual(scan_index(self.root)["index_sha256"],
                         hashlib.sha256(self.git("ls-files", "--stage", "-z")).hexdigest())

    def test_cli_codes_and_redacted_output(self):
        def run(*extra):
            return subprocess.run([sys.executable, "-m", "secretlens", "--repo", str(self.root), *extra],
                                  capture_output=True, text=True)
        self.assertEqual(run().returncode, 0)
        self.stage("secret", token().encode())
        result = run()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(token(), result.stdout + result.stderr)
        self.assertFalse(json.loads(result.stdout)["clean"])
        result = run("--max-blob-bytes", "1")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)["complete"])

    def test_git_failure_has_no_sensitive_stderr(self):
        with patch("secretlens.core.subprocess.run", return_value=
                   subprocess.CompletedProcess([], 128, b"", token().encode())):
            with self.assertRaises(ScanError) as caught:
                scan_index(self.root)
        self.assertNotIn(token(), str(caught.exception))


if __name__ == "__main__":
    unittest.main()
