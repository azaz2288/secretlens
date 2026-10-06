"""Opt-in local Git hook installation; never replace another hook."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

from . import __version__
from .core import DEFAULT_MAX_FINDINGS, ScanError
from .policy import apply_policy, load_policy

MARKER = '# SecretLens managed pre-commit hook v1'
CONFIG_PREFIX = '# secretlens-config: '
MAX_HOOK_BYTES = 16384


def _linked(path):
    return path.is_symlink() or path.is_junction()


def _git(repository, *args, allowed=(0,)):
    # Installation acts on the explicit repo, not a hook caller's alternate
    # index/worktree variables. The *scanner* intentionally retains those.
    env = {key: value for key, value in os.environ.items() if key not in {
        'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
        'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_PREFIX'}}
    try:
        result = subprocess.run(['git', '-C', str(repository), *args], env=env,
                                capture_output=True, timeout=30)
        if result.returncode not in allowed:
            raise ScanError('Cannot establish a private local hook location')
        return result
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError('Git unavailable or timed out during hook operation') from exc


def _location(repository):
    repository = Path(repository).absolute()
    if _linked(repository) or not repository.is_dir():
        raise ScanError('Hook operation requires a regular repository root')
    git_dir = repository / '.git'
    if _linked(git_dir) or not git_dir.is_dir():
        raise ScanError('Bare, linked worktree, submodule and external Git directories are unsupported')
    try:
        actual = Path(_git(repository, 'rev-parse', '--absolute-git-dir').stdout.decode('utf-8').strip())
    except UnicodeError as exc:
        raise ScanError('Git directory path cannot be decoded') from exc
    if actual.resolve() != git_dir.resolve():
        raise ScanError('Shared or external Git directory refused')
    config = _git(repository, 'config', '--get', 'core.hooksPath', allowed=(0, 1))
    if config.returncode == 0:
        raise ScanError('Configured core.hooksPath refused; integrate the gate manually')
    hooks = git_dir / 'hooks'
    if _linked(hooks) or (hooks.exists() and not hooks.is_dir()):
        raise ScanError('Hook directory must not be linked or non-directory')
    return hooks / 'pre-commit'


def _config(config):
    legacy_keys = {'python', 'approvals', 'max_blob_bytes', 'max_total_bytes', 'max_files'}
    if not isinstance(config, dict) or set(config) not in (legacy_keys, legacy_keys | {'max_findings'}):
        raise ScanError('Unsupported managed hook configuration')
    for key in ('python', 'approvals'):
        value = config[key]
        if key == 'approvals' and value is None:
            continue
        if (not isinstance(value, str) or not value or not Path(value).is_absolute()
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ScanError('Hook runtime and approval paths must be absolute, control-free paths')
    if any(type(config[key]) is not int or config[key] < 1
           for key in ('max_blob_bytes', 'max_total_bytes', 'max_files', 'max_findings') if key in config):
        raise ScanError('Scan limits must be positive integers')
    return config


def _render(config):
    _config(config)
    encoded = base64.b64encode(json.dumps(config, sort_keys=True, ensure_ascii=True,
                                         separators=(',', ':')).encode()).decode('ascii')
    # -I discards cwd/PYTHONPATH/PYTHONHOME from package lookup. Retain Git's
    # GIT_INDEX_FILE so partial commits scan their actual temporary index.
    command = [config['python'].replace('\\', '/'), '-I', '-m', 'secretlens', '--repo', '.',
               '--max-blob-bytes', str(config['max_blob_bytes']),
               '--max-total-bytes', str(config['max_total_bytes']), '--max-files', str(config['max_files'])]
    # Preserve exact v0.4/v0.5 hook bytes for unchanged legacy-hook removal.
    if 'max_findings' in config:
        command.extend(['--max-findings', str(config['max_findings'])])
    if config['approvals'] is not None:
        command.extend(['--approvals', config['approvals'].replace('\\', '/')])
    content = ('#!/bin/sh\n' + MARKER + '\n' + CONFIG_PREFIX + encoded + '\nexec '
               + ' '.join(shlex.quote(value) for value in command) + '\n').encode('utf-8')
    if len(content) > MAX_HOOK_BYTES:
        raise ScanError('Generated hook exceeds size limit')
    return content


def _runtime(python):
    try:
        result = subprocess.run([str(python), '-I', '-c',
                                 'import sys, secretlens; from secretlens.core import scan_index; '
                                 'assert sys.version_info >= (3,12); print(secretlens.__version__)'],
                                capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError('Hook Python runtime unavailable') from exc
    if result.returncode or result.stdout.strip() != __version__.encode('ascii'):
        raise ScanError('Install this SecretLens version into the selected isolated Python environment first')


def install_hook(repository, *, python=None, approvals=None, max_blob_bytes=1024 * 1024,
                 max_total_bytes=32 * 1024 * 1024, max_files=10000, max_findings=DEFAULT_MAX_FINDINGS):
    python = Path(python or sys.executable).absolute()  # Do not resolve venv symlinks to the base interpreter.
    config = {'python': str(python), 'approvals': None if approvals is None else str(Path(approvals).absolute()),
              'max_blob_bytes': max_blob_bytes, 'max_total_bytes': max_total_bytes, 'max_files': max_files,
              'max_findings': max_findings}
    content = _render(config)
    target = _location(repository)
    if target.exists() or _linked(target):
        raise ScanError('An existing pre-commit hook is never overwritten')
    _runtime(python)
    if approvals is not None:
        apply_policy({'complete': True, 'clean': True, 'findings': []}, load_policy(Path(config['approvals'])))
    temporary = None
    try:
        target.parent.mkdir(exist_ok=True)
        with tempfile.NamedTemporaryFile('wb', dir=target.parent, prefix='.secretlens-', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o700)
        os.link(temporary, target)
        return {'complete': True, 'action': 'installed', 'sha256': hashlib.sha256(content).hexdigest(),
                'scope': 'entire-git-index', 'isolated_runtime': True}
    except OSError as exc:
        raise ScanError('Hook publication failed or another hook already exists') from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def uninstall_hook(repository):
    target = _location(repository)
    if _linked(target) or not target.is_file():
        raise ScanError('No regular managed hook to remove')
    try:
        def fingerprint(info):
            # Reading may change access time; that is not a user modification.
            return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns
        before = fingerprint(target.stat())
        with target.open('rb') as stream:
            content = stream.read(MAX_HOOK_BYTES + 1)
        lines = content.decode('utf-8').splitlines()
        if len(content) > MAX_HOOK_BYTES or len(lines) != 4 or lines[1] != MARKER or not lines[2].startswith(CONFIG_PREFIX):
            raise ScanError('Only an unchanged generated SecretLens hook may be removed')
        config = json.loads(base64.b64decode(lines[2][len(CONFIG_PREFIX):], validate=True))
        if _render(config) != content or before != fingerprint(target.stat()):
            raise ScanError('Managed hook was changed; preserve it for manual review')
        target.unlink()
        return {'complete': True, 'action': 'uninstalled', 'sha256': hashlib.sha256(content).hexdigest()}
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ScanError('Managed hook cannot be verified or removed') from exc
