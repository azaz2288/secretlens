from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import venv
from unittest.mock import patch

from secretlens.core import ScanError, scan_index
from secretlens.hooks import install_hook, uninstall_hook


def token():
    return 'gh' + 'p_' + 'A1b2' * 9


class HookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime_temp = tempfile.TemporaryDirectory(prefix="SecretLens runtime's ")
        cls.runtime_root = Path(cls.runtime_temp.name)
        venv.EnvBuilder(with_pip=False).create(cls.runtime_root)
        cls.python = cls.runtime_root / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        purelib = subprocess.check_output([str(cls.python), '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'], text=True).strip()
        # Test-only installed-runtime fixture. Real wheel installation is a
        # separate release smoke check, not claimed by this copy.
        shutil.copytree(Path(__file__).resolve().parents[1] / 'secretlens', Path(purelib) / 'secretlens',
                        ignore=shutil.ignore_patterns('__pycache__'))

    @classmethod
    def tearDownClass(cls):
        cls.runtime_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hook repo's 中文 ")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic Test')
        self.git('config', 'user.email', 'test@example.invalid')
        self.hook = self.repo / '.git/hooks/pre-commit'

    def git(self, *args, env=None, check=True):
        result = subprocess.run(['git', '-C', str(self.repo), *args], env=env,
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def install(self, **kwargs):
        return install_hook(self.repo, python=self.python, **kwargs)

    def stage(self, value):
        (self.repo / 'value.txt').write_text(value)
        self.git('add', 'value.txt')

    def test_clean_commit_then_staged_secret_is_blocked_without_disclosure(self):
        result = self.install()
        self.assertEqual(result['action'], 'installed')
        self.stage('clean')
        self.git('commit', '-qm', 'clean baseline')
        original = self.git('rev-parse', 'HEAD').stdout
        self.stage(token())
        (self.repo / 'value.txt').write_text('worktree cleaned, staged secret remains')
        rejected = self.git('commit', '-qm', 'must reject', check=False)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('github-token', rejected.stdout + rejected.stderr)
        self.assertNotIn(token(), rejected.stdout + rejected.stderr)
        self.assertEqual(self.git('rev-parse', 'HEAD').stdout, original)

    def test_repository_module_and_pythonpath_cannot_shadow_installed_gate(self):
        self.install()
        (self.repo / 'secretlens.py').write_text('raise SystemExit(0)')
        self.stage(token())
        env = {**os.environ, 'PYTHONPATH': str(self.repo), 'PYTHONHOME': str(self.repo)}
        result = self.git('commit', '-qm', 'blocked', env=env, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('github-token', result.stdout + result.stderr)

    def test_git_partial_commit_checks_actual_temporary_index(self):
        self.install()
        self.stage('clean')
        self.git('commit', '-qm', 'baseline')
        self.stage(token())
        (self.repo / 'safe.txt').write_text('safe partial commit')
        self.git('add', 'safe.txt')
        self.git('commit', '-qm', 'only safe file', '--', 'safe.txt')
        self.assertEqual(self.git('show', 'HEAD:value.txt').stdout, 'clean')
        self.assertFalse(scan_index(self.repo)['clean'])
        self.assertNotEqual(self.git('commit', '-qm', 'remaining secret', check=False).returncode, 0)

    def test_missing_runtime_after_installation_blocks_commit(self):
        # Do not damage the shared fixture runtime: use a separate copy.
        root = self.repo / 'runtime-copy'
        shutil.copytree(self.runtime_root, root)
        executable = root / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        install_hook(self.repo, python=executable)
        executable.unlink()
        self.stage('clean')
        self.assertNotEqual(self.git('commit', '-qm', 'cannot check', check=False).returncode, 0)

    def test_existing_and_modified_hooks_are_never_overwritten_or_removed(self):
        self.hook.write_text('#!/bin/sh\nexit 7\n')
        before = self.hook.read_bytes()
        with self.assertRaises(ScanError):
            self.install()
        with self.assertRaises(ScanError):
            uninstall_hook(self.repo)
        self.assertEqual(self.hook.read_bytes(), before)
        self.hook.unlink()
        self.install()
        self.hook.write_bytes(self.hook.read_bytes() + b'# custom changes\n')
        with self.assertRaises(ScanError):
            uninstall_hook(self.repo)
        self.assertTrue(self.hook.exists())

    def test_roundtrip_uninstall_removes_only_original_generated_hook(self):
        sample = self.repo / '.git/hooks/another-hook'
        sample.write_text('keep')
        installed = self.install()
        removed = uninstall_hook(self.repo)
        self.assertEqual(installed['sha256'], removed['sha256'])
        self.assertFalse(self.hook.exists())
        self.assertEqual(sample.read_text(), 'keep')
        with self.assertRaises(ScanError):
            uninstall_hook(self.repo)

    def test_custom_hookspath_rejected_without_external_writes(self):
        external = self.repo / 'custom-hooks'
        self.git('config', 'core.hooksPath', str(external))
        with self.assertRaises(ScanError):
            self.install()
        self.assertFalse(external.exists())
        self.assertFalse(self.hook.exists())

    def test_linked_worktree_and_subdirectory_rejected(self):
        self.stage('clean')
        self.git('commit', '-qm', 'baseline')
        linked = self.repo / 'linked'
        self.git('worktree', 'add', '-b', 'linked-test', str(linked))
        with self.assertRaises(ScanError):
            install_hook(linked, python=self.python)
        nested = self.repo / 'nested'
        nested.mkdir()
        with self.assertRaises(ScanError):
            install_hook(nested, python=self.python)
        self.assertFalse(self.hook.exists())

    def test_limit_failure_stops_commit(self):
        self.install(max_blob_bytes=3)
        self.stage('long but not secret')
        result = self.git('commit', '-qm', 'over limit', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('coverage is incomplete', result.stdout + result.stderr)

    def test_finding_budget_bound_to_hook_blocks_approved_overflow(self):
        self.stage((token() + '\n') * 2)
        finding = scan_index(self.repo)['findings'][0]
        policy = self.repo / 'trusted.json'
        policy.write_text(json.dumps({'version': 1, 'approvals': [{
            'path': 'value.txt', 'rule': finding['rule'], 'fingerprint': finding['fingerprint'],
            'reviewer': 'synthetic reviewer', 'reason': 'synthetic density fixture',
            'expires_at': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat()}]}))
        self.install(max_findings=1, approvals=policy)
        content = self.hook.read_bytes()
        self.assertIn(b'--max-findings 1', content)
        before = self.git('ls-files', '--stage', '-z').stdout
        result = self.git('commit', '-qm', 'over budget', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Finding count exceeds scan limit', result.stdout + result.stderr)
        self.assertNotIn(token(), result.stdout + result.stderr)
        self.assertEqual(before, self.git('ls-files', '--stage', '-z').stdout)
        uninstall_hook(self.repo)
        self.install(max_findings=2, approvals=policy)
        self.git('commit', '-qm', 'explicit synthetic approved budget')

    def test_invalid_finding_budget_creates_no_hook(self):
        for value in (0, -1, True, False, 2.5, '2', None):
            with self.subTest(value=value), self.assertRaises(ScanError):
                self.install(max_findings=value)
            self.assertFalse(self.hook.exists())

    def test_unchanged_legacy_hook_can_be_removed_without_new_configuration(self):
        import base64
        import shlex
        from secretlens.hooks import MARKER, CONFIG_PREFIX
        config = {'python': str(self.python.absolute()), 'approvals': None,
                  'max_blob_bytes': 1048576, 'max_total_bytes': 33554432, 'max_files': 10000}
        encoded = base64.b64encode(json.dumps(config, sort_keys=True, ensure_ascii=True,
                                              separators=(',', ':')).encode()).decode('ascii')
        command = [config['python'].replace('\\', '/'), '-I', '-m', 'secretlens', '--repo', '.',
                   '--max-blob-bytes', '1048576', '--max-total-bytes', '33554432', '--max-files', '10000']
        original = ('#!/bin/sh\n' + MARKER + '\n' + CONFIG_PREFIX + encoded + '\nexec '
                    + ' '.join(shlex.quote(value) for value in command) + '\n').encode()
        self.hook.write_bytes(original)
        result = uninstall_hook(self.repo)
        self.assertEqual(result['action'], 'uninstalled')
        self.assertFalse(self.hook.exists())

    def test_explicit_approval_used_but_repo_policy_not_auto_loaded(self):
        self.stage(token())
        finding = scan_index(self.repo)['findings'][0]
        policy = self.repo / 'trusted review.json'
        policy.write_text(json.dumps({'version': 1, 'approvals': [{
            'path': 'value.txt', 'rule': finding['rule'], 'fingerprint': finding['fingerprint'],
            'reviewer': 'synthetic reviewer', 'reason': 'invalid synthetic token',
            'expires_at': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat()}]}))
        self.install()
        self.assertNotEqual(self.git('commit', '-qm', 'no implicit approval', check=False).returncode, 0)
        uninstall_hook(self.repo)
        self.install(approvals=policy)
        self.git('commit', '-qm', 'explicit synthetic approval')

    def test_invalid_runtime_or_policy_creates_no_hook(self):
        for kwargs in ({'python': self.repo / 'missing-python'}, {'python': self.python, 'max_files': True},
                       {'python': self.python, 'approvals': self.repo / 'missing.json'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ScanError):
                install_hook(self.repo, **kwargs)
            self.assertFalse(self.hook.exists())

    def test_concurrent_installs_have_one_complete_winner(self):
        def attempt(_):
            try:
                self.install()
                return True
            except ScanError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(attempt, range(2))), 1)
        self.assertEqual(list(self.hook.parent.glob('.secretlens-*')), [])
        uninstall_hook(self.repo)

    def test_failed_exclusive_publication_leaves_no_hook_or_temp(self):
        with patch('secretlens.hooks.os.link', side_effect=OSError('unsupported')):
            with self.assertRaises(ScanError):
                self.install()
        self.assertFalse(self.hook.exists())
        self.assertEqual(list(self.hook.parent.glob('.secretlens-*')), [])

    def test_cli_install_and_uninstall_using_isolated_runtime(self):
        for action in ('--install-hook', '--uninstall-hook'):
            result = subprocess.run([str(self.python), '-I', '-m', 'secretlens', '--repo', str(self.repo), action],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(json.loads(result.stdout)['complete'])

    def test_symlink_hook_refused(self):
        destination = self.repo / 'outside-hook'
        destination.write_text('do not touch')
        try:
            self.hook.symlink_to(destination)
        except (OSError, NotImplementedError):
            self.skipTest('symlink unavailable')
        with self.assertRaises(ScanError):
            self.install()
        with self.assertRaises(ScanError):
            uninstall_hook(self.repo)
        self.assertEqual(destination.read_text(), 'do not touch')

    def test_linked_hook_directory_refused_without_touching_target(self):
        hooks = self.hook.parent
        hooks.rename(self.repo / 'saved-hooks')
        destination = self.repo / 'outside-hooks'
        destination.mkdir()
        sentinel = destination / 'keep.txt'
        sentinel.write_text('keep')
        if os.name == 'nt':
            result = subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(hooks), str(destination)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0)
        else:
            hooks.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(ScanError):
            self.install()
        with self.assertRaises(ScanError):
            uninstall_hook(self.repo)
        self.assertEqual(sentinel.read_text(), 'keep')
        self.assertFalse((destination / 'pre-commit').exists())

    def test_malformed_managed_hook_and_invalid_policy_are_preserved(self):
        from secretlens.hooks import MARKER, CONFIG_PREFIX
        for content in (b'empty', ('#!/bin/sh\n' + MARKER + '\n' + CONFIG_PREFIX + 'not-base64\nexec anything\n').encode()):
            self.hook.write_bytes(content)
            with self.assertRaises(ScanError):
                uninstall_hook(self.repo)
            self.assertEqual(self.hook.read_bytes(), content)
        self.hook.unlink()
        policy = self.repo / 'invalid-policy.json'
        policy.write_text('{}')
        with self.assertRaises(ScanError):
            self.install(approvals=policy)
        self.assertFalse(self.hook.exists())

    def test_bare_repo_rejected(self):
        bare = self.repo / 'bare'
        self.git('init', '--bare', str(bare))
        with self.assertRaises(ScanError):
            install_hook(bare, python=self.python)
        self.assertFalse((bare / 'hooks/pre-commit').exists())


if __name__ == '__main__':
    unittest.main()
