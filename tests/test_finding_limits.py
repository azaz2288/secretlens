"""Only synthetic candidate-density inputs; runnable against installed wheels."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from secretlens.__main__ import main
from secretlens.core import ScanError, scan_blob, scan_index


def token():
    return 'gh' + 'p_' + 'A1b2' * 9


class FindingBudgetTests(unittest.TestCase):
    def test_exact_blob_budget_and_zero_clean_remainder(self):
        self.assertEqual(len(scan_blob('a', (token() + '\n').encode() * 2, max_findings=2)), 2)
        self.assertEqual(scan_blob('a', b'clean', max_findings=0), [])
        with self.assertRaises(ScanError):
            scan_blob('a', token().encode(), max_findings=0)

    def test_blob_overflow_never_returns_partial_findings(self):
        with self.assertRaisesRegex(ScanError, 'Finding count exceeds scan limit') as caught:
            scan_blob('a', (token() + '\n').encode() * 3, max_findings=2)
        self.assertNotIn(token(), str(caught.exception))

    def test_default_blob_budget_fails_closed(self):
        with self.assertRaises(ScanError):
            scan_blob('a', (token() + '\n').encode() * 10001)

    def test_budget_counts_overlapping_rules_and_duplicate_occurrences(self):
        blob = ('password = "' + token() + '"').encode()
        self.assertEqual(len(scan_blob('a', blob, max_findings=2)), 2)
        with self.assertRaises(ScanError):
            scan_blob('a', blob, max_findings=1)

    def test_invalid_blob_limits_before_decode(self):
        for value in (True, False, -1, 1.5, '2', None):
            with self.subTest(value=value), patch('secretlens.core._text') as decoder:
                with self.assertRaises(ScanError):
                    scan_blob('a', b'clean', max_findings=value)
                decoder.assert_not_called()

    def test_segmented_positions_match_independent_prefix_oracle(self):
        text = '前言\r\n' + token() + ' ' + token() + '\r\n\n'
        text += 'password="' + token() + '"\n' + 'AK' + 'IA' + 'B' * 16
        text += '\n-----BEGIN ' + 'RSA PRIVATE KEY-----\n'
        for encoding in ('utf-8-sig', 'utf-16', 'utf-32'):
            with self.subTest(encoding=encoding):
                findings = scan_blob('文件', text.encode(encoding), max_findings=10)
                from secretlens.core import RULES
                expected = []
                for rule, pattern, group in RULES:
                    for match in pattern.finditer(text):
                        start = match.start(group)
                        fingerprint = hashlib.sha256('文件'.encode() + b'\0' + rule.encode()
                                                     + b'\0' + match.group(group).encode()).hexdigest()
                        expected.append({'path': '文件', 'rule': rule,
                                         'line': text.count('\n', 0, start) + 1,
                                         'column': start - text.rfind('\n', 0, start),
                                         'fingerprint': fingerprint})
                self.assertEqual(findings, sorted(expected, key=lambda f: (f['line'], f['column'], f['rule'])))

    def test_dense_position_work_does_not_rescan_prior_prefixes(self):
        class MeasuredText(str):
            counted = 0
            searched = 0
            def count(self, sub, start=0, end=None):
                self.counted += (len(self) if end is None else end) - start
                return super().count(sub, start, end)
            def rfind(self, sub, start=0, end=None):
                self.searched += (len(self) if end is None else end) - start
                return super().rfind(sub, start, end)
        content = MeasuredText((token() + '\n') * 200)
        with patch('secretlens.core._text', return_value=content):
            findings = scan_blob('a', b'fixture')
        self.assertEqual(len(findings), 200)
        self.assertLessEqual(content.counted + content.searched, len(content) * 2)


class IndexBudgetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='secretlens-density-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git('init', '-q')

    def git(self, *args):
        result = subprocess.run(['git', '-C', str(self.root), *args], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0)
        return result.stdout

    def stage(self, name, text):
        (self.root / name).write_text(text, encoding='utf-8')
        self.git('add', name)

    def test_index_budget_shared_across_paths_including_duplicate_blobs(self):
        for name in ('a', 'b'):
            self.stage(name, token())
        self.assertEqual(len(scan_index(self.root, max_findings=2)['findings']), 2)
        with self.assertRaises(ScanError):
            scan_index(self.root, max_findings=1)

    def test_exact_index_limit_still_checks_clean_following_files(self):
        self.stage('a', token())
        self.stage('z', 'clean')
        report = scan_index(self.root, max_findings=1)
        self.assertTrue(report['complete'])
        self.assertEqual(report['files_scanned'], 2)
        self.assertFalse(report['clean'])

    def test_invalid_index_limit_precedes_git_io(self):
        for value in (0, -1, True, False, 1.5, '3', None):
            with self.subTest(value=value), patch('secretlens.core._git') as git:
                with self.assertRaises(ScanError):
                    scan_index(self.root, max_findings=value)
                git.assert_not_called()

    def test_overflow_closes_blob_iterator(self):
        self.stage('a', token())
        self.stage('b', token())
        closed = []
        def blobs(*args):
            try:
                yield 'a', token().encode()
                yield 'b', token().encode()
                self.fail('requested content beyond overflow')
            finally:
                closed.append(True)
        with patch('secretlens.core._batch_blobs', blobs), self.assertRaises(ScanError):
            scan_index(self.root, max_findings=1)
        self.assertEqual(closed, [True])

    def test_cli_overflow_redacted_exit_two_and_approval_not_applied(self):
        self.stage('a', (token() + '\n') * 2)
        original = self.git('ls-files', '--stage', '-z')
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), patch('secretlens.__main__.load_policy') as policy:
            code = main(['--repo', str(self.root), '--max-findings', '1', '--approvals', 'unused-policy'])
        self.assertEqual(code, 2)
        policy.assert_not_called()
        report = json.loads(stream.getvalue())
        self.assertFalse(report['complete'])
        self.assertFalse(report['clean'])
        self.assertNotIn('findings', report)
        self.assertNotIn(token(), stream.getvalue())
        self.assertEqual(self.git('ls-files', '--stage', '-z'), original)

    def test_real_subprocess_limit_and_default_cli(self):
        self.stage('a', (token() + '\n') * 2)
        import sys
        for extra, expected in ((['--max-findings', '1'], 2), ([], 1)):
            result = subprocess.run([sys.executable, '-m', 'secretlens', '--repo', str(self.root), *extra],
                                    capture_output=True, timeout=15)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertNotIn(token().encode(), result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
