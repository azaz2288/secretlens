"""Offline, deterministic synthetic rule evaluation, not credential validation."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import re

from . import __version__
from .core import RULES, ScanError, scan_blob

# Labels are constructed independently of the scanner. No real credentials,
# repository files, provider calls or model APIs enter this evaluation.
RULE_NAMES = ('github-token', 'aws-access-id', 'private-key', 'assigned-secret')


@dataclass(frozen=True)
class Expected:
    rule: str
    line: int
    column: int


@dataclass(frozen=True)
class Case:
    name: str
    cohort: str
    blob: bytes
    expected: tuple[Expected, ...]


def corpus() -> tuple[Case, ...]:
    cases = []
    encodings = (
        ('utf8', 'utf-8', b''), ('utf8-bom', 'utf-8', b'\xef\xbb\xbf'),
        ('utf16le-bom', 'utf-16-le', b'\xff\xfe'),
        ('utf16be-bom', 'utf-16-be', b'\xfe\xff'),
        ('utf32le-bom', 'utf-32-le', b'\xff\xfe\x00\x00'),
        ('utf32be-bom', 'utf-32-be', b'\x00\x00\xfe\xff'),
    )

    def add(name, text, expected=(), cohort='supported', encode=True):
        if encode:
            for label, encoding, bom in encodings:
                cases.append(Case(name + '-' + label, cohort, bom + text.encode(encoding), tuple(expected)))
        else:
            cases.append(Case(name, cohort, text, tuple(expected)))

    def positive(name, value, rule, prefix='', suffix=''):
        # Line 2 and Unicode columns exercise metadata, not bytes-as-columns.
        text = 'synthetic sample\r\n' + '中文: ' + prefix + value + suffix + '\n'
        add(name, text, (Expected(rule, 2, 5 + len(prefix)),))

    for letter in 'pousr':
        for length in (36, 37, 255):
            value = 'gh' + letter + '_' + 'A1b2' * (length // 4) + 'Z' * (length % 4)
            positive(f'github-{letter}-{length}', value, 'github-token', '(', ')')
        for length in (35, 256):
            add(f'github-{letter}-invalid-{length}', 'gh' + letter + '_' + 'A' * length)
    for length in (40, 255):
        positive(f'github-fine-{length}', 'github' + '_pat_' + 'B' * length, 'github-token')
    for length in (39, 256):
        add(f'github-fine-invalid-{length}', 'github' + '_pat_' + 'B' * length)
    github = 'gh' + 'p_' + 'A1b2' * 9
    for name, before, after in (('left-word', 'a', ''), ('right-word', '', '_'),
                                ('underscore', '_', ''), ('unicode-word', '中', '')):
        add('github-boundary-' + name, before + github + after)
    for prefix in ('AK' + 'IA', 'AS' + 'IA'):
        positive('aws-' + prefix.lower(), prefix + 'A1' * 8, 'aws-access-id')
        for length in (15, 17):
            add('aws-invalid-' + prefix.lower() + '-' + str(length), prefix + 'A' * length)
        add('aws-lowercase-' + prefix.lower(), prefix.lower() + 'a' * 16)
    for kind in ('', 'RSA ', 'EC ', 'DSA ', 'OPENSSH ', 'ENCRYPTED '):
        marker = '-----BEGIN ' + kind + 'PRIVATE KEY-----'
        positive('key-' + (kind.strip().lower() or 'generic'), marker, 'private-key')
    add('key-public', '-----BEGIN PUBLIC KEY-----')
    add('key-certificate', '-----BEGIN CERTIFICATE-----')
    for field in ('api_key', 'api-key', 'access_token', 'auth-token', 'client_secret',
                  'password', 'secret_key', 'APIKEY'):
        for length in (16, 512):
            for quote in ('single', 'double'):
                q = "'" if quote == 'single' else '"'
                assignment = q + field + q + ' : ' + q
                positive(f'assigned-{field.lower()}-{length}-{quote}', 'V' * length,
                         'assigned-secret', assignment, q)
        for length in (15, 513):
            add(f'assigned-invalid-{field.lower()}-{length}', field + '="' + 'V' * length + '"')
    add('assigned-unquoted', 'password=' + 'V' * 32)
    add('assigned-other-field', 'description="' + 'V' * 32 + '"')
    add('assigned-word-prefix', 'not_password="' + 'V' * 32 + '"')
    add('assigned-multiline', 'password="' + 'V' * 8 + '\n' + 'V' * 16 + '"')
    add('benign-source', 'print("hello")\ncount = 100\n')
    add('empty', '')
    # Multiple rules and repeated occurrences require exact localization/counts.
    aws = 'AK' + 'IA' + 'A1' * 8
    add('overlap', 'password="' + github + '"\n' + aws + '\n' + github,
        (Expected('assigned-secret', 1, 11), Expected('github-token', 1, 11),
         Expected('aws-access-id', 2, 1), Expected('github-token', 3, 1)))
    add('binary-ascii', b'\x00\xff\x80\n' + github.encode() + b'\x00',
        (Expected('github-token', 2, 1),), encode=False)

    # Deliberately keep misses AND benign lookalikes in the overall denominator.
    # "Intended credential" is a synthetic task label, not a proven live key.
    gap_values = (
        ('github', github, 'github-token'), ('aws', aws, 'aws-access-id'),
        ('key', '-----BEGIN ' + 'PRIVATE KEY-----', 'private-key'),
        ('assigned', 'password="' + 'V' * 24 + '"', 'assigned-secret'),
    )
    for name, value, rule in gap_values:
        column = 11 if rule == 'assigned-secret' else 1
        for encoding in ('utf-16-le', 'utf-16-be', 'utf-32-le', 'utf-32-be'):
            add('gap-' + name + '-' + encoding, value.encode(encoding),
                (Expected(rule, 1, column),), 'known-gap', encode=False)
        escaped = ''.join('\\u' + format(ord(char), '04x') for char in value)
        add('gap-' + name + '-escaped-json', escaped.encode(),
            (Expected(rule, 1, column),), 'known-gap', encode=False)
    # A documented test placeholder has no intended credential, but still
    # matches the candidate rule; callers must not silently blanket-ignore it.
    add('gap-placeholder', ('password="' + 'example-' * 3 + '"').encode(),
        cohort='known-gap', encode=False)
    add('gap-short-password', ('password="' + 'V' * 12 + '"').encode(),
        (Expected('assigned-secret', 1, 11),), 'known-gap', encode=False)
    return tuple(cases)


def _metrics(counts):
    tp, fp, fn = counts['tp'], counts['fp'], counts['fn']
    return {**counts, 'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None}


def evaluate(cases=None, *, scanner=scan_blob) -> dict:
    cases = corpus() if cases is None else tuple(cases)
    if not cases:
        raise ScanError('Evaluation requires nonempty synthetic cases')
    names = set()
    records = []
    for case in cases:
        if (not isinstance(case, Case) or not isinstance(case.name, str)
                or not re.fullmatch(r'[a-z0-9_-]{1,100}', case.name)
                or case.name in names or case.cohort not in ('supported', 'known-gap')
                or not isinstance(case.blob, bytes) or not isinstance(case.expected, tuple)):
            raise ScanError('Invalid or duplicate synthetic evaluation case')
        names.add(case.name)
        if any(not isinstance(item, Expected) or item.rule not in RULE_NAMES
               or type(item.line) is not int or type(item.column) is not int
               or item.line < 1 or item.column < 1 for item in case.expected):
            raise ScanError('Invalid synthetic truth label')
        if len(set(case.expected)) != len(case.expected):
            raise ScanError('Duplicate synthetic truth label')
        records.append({'case': case.name, 'cohort': case.cohort,
                        'blob_sha256': hashlib.sha256(case.blob).hexdigest(),
                        'truth': [[e.rule, e.line, e.column] for e in case.expected]})
    # Digest binds both bytes and independently constructed labels; stable
    # against input ordering. No corpus text enters the public report.
    digest = hashlib.sha256(json.dumps(sorted(records, key=lambda r: r['case']),
                                      sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    counts = {cohort: {rule: dict(tp=0, fp=0, fn=0, tn=0) for rule in RULE_NAMES}
              for cohort in ('supported', 'known-gap', 'overall')}
    mismatches = []
    cohort_sizes = Counter(case.cohort for case in cases)
    for case in sorted(cases, key=lambda c: c.name):
        try:
            findings = scanner('synthetic/' + case.name, case.blob)
            actual = Counter()
            for finding in findings:
                rule, line, column = finding['rule'], finding['line'], finding['column']
                if (rule not in RULE_NAMES or type(line) is not int or type(column) is not int
                        or line < 1 or column < 1):
                    raise ValueError('invalid finding')
                actual[(rule, line, column)] += 1
        except Exception as exc:
            # A scanner failure must not become a negative or echo sample text.
            raise ScanError('Synthetic evaluation scanner failed or returned invalid metadata') from exc
        expected = Counter((e.rule, e.line, e.column) for e in case.expected)
        for rule in RULE_NAMES:
            intended = any(item[0] == rule for item in expected)
            detected = any(item[0] == rule for item in actual)
            label = 'tp' if intended and detected else 'fp' if detected else 'fn' if intended else 'tn'
            for cohort in (case.cohort, 'overall'):
                counts[cohort][rule][label] += 1
        if actual != expected:
            mismatches.append({'case': case.name, 'cohort': case.cohort,
                               'missing_occurrences': sum((expected - actual).values()),
                               'unexpected_occurrences': sum((actual - expected).values())})
    rule_digest = hashlib.sha256(json.dumps([(n, p.pattern, p.flags, g) for n, p, g in RULES],
                                            separators=(',', ':')).encode()).hexdigest()
    return {'version': 1, 'scanner_version': __version__, 'corpus_version': 1,
            'scope': 'synthetic-rule-evaluation-not-live-credential-validation',
            'unit': 'per-rule-per-sample-presence', 'synthetic_only': True,
            'corpus_sha256': digest, 'rules_sha256': rule_digest,
            'samples': len(cases), 'cohorts': dict(sorted(cohort_sizes.items())),
            'supported_passed': not any(m['cohort'] == 'supported' for m in mismatches),
            'metrics': {c: {r: _metrics(v) for r, v in rules.items()} for c, rules in counts.items()},
            'localization_and_count_mismatches': mismatches}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Exit 1 for supported localization/count regressions; known gaps remain reported')
    args = parser.parse_args(argv)
    try:
        report = evaluate()
        print(json.dumps(report, ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2))
        return int(args.check and not report['supported_passed'])
    except ScanError:
        print(json.dumps({'complete': False, 'error': 'Synthetic evaluation failed'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
