"""Use an installed runtime to demonstrate a gate only in a temporary repo."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from secretlens.core import scan_index
from secretlens.hooks import install_hook, uninstall_hook


with tempfile.TemporaryDirectory(prefix="SecretLens hook demo's ") as temporary:
    repo = Path(temporary)
    def git(*args):
        return subprocess.run(['git', '-C', str(repo), *args], capture_output=True,
                              text=True, encoding='utf-8', errors='replace', timeout=15)
    assert git('init', '-q').returncode == 0
    assert git('config', 'user.name', 'Synthetic Demo').returncode == 0
    assert git('config', 'user.email', 'demo@example.invalid').returncode == 0
    installed = install_hook(repo, python=sys.executable)
    sample = repo / 'sample.txt'
    sample.write_text('no credential')
    assert git('add', 'sample.txt').returncode == 0
    assert git('commit', '-qm', 'clean synthetic baseline').returncode == 0
    baseline = git('rev-parse', 'HEAD').stdout
    candidate = 'gh' + 'p_' + 'A1b2' * 9
    sample.write_text(candidate)
    assert git('add', 'sample.txt').returncode == 0
    sample.write_text('worktree cleaned after staging')
    rejected = git('commit', '-qm', 'must be rejected')
    assert rejected.returncode != 0
    assert 'github-token' in rejected.stdout + rejected.stderr
    assert candidate not in rejected.stdout + rejected.stderr
    assert git('rev-parse', 'HEAD').stdout == baseline
    assert not scan_index(repo)['clean']
    removed = uninstall_hook(repo)
    assert installed['sha256'] == removed['sha256']
    assert not (repo / '.git/hooks/pre-commit').exists()
    assert not scan_index(repo)['clean']  # Uninstall doesn't alter the index.
    print(json.dumps({'synthetic_temporary_repo_only': True, 'clean_commit_passed': True,
                      'staged_candidate_blocked': True, 'candidate_not_disclosed': True,
                      'original_head_preserved': True, 'managed_hook_removed': True,
                      'staged_bytes_unchanged_after_removal': True}))
