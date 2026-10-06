"""Repeated synthetic dense-blob comparisons; not real-world detection evidence."""
import argparse
import hashlib
import json
import platform
import statistics
import time
import tracemalloc

from secretlens.core import RULES, scan_blob


def prefix_reference(path, content):
    """Original prefix-location algorithm, retained only as a benchmark oracle."""
    findings = []
    for rule, pattern, group in RULES:
        for match in pattern.finditer(content):
            start = match.start(group)
            digest = hashlib.sha256(path.encode() + b'\0' + rule.encode()
                                    + b'\0' + match.group(group).encode()).hexdigest()
            findings.append({'path': path, 'rule': rule,
                             'line': content.count('\n', 0, start) + 1,
                             'column': start - content.rfind('\n', 0, start),
                             'fingerprint': digest})
    return sorted(findings, key=lambda item: (item['line'], item['column'], item['rule']))


def measure(call):
    tracemalloc.start()
    start = time.perf_counter()
    result = call()
    elapsed = time.perf_counter() - start
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return result, {'seconds': round(elapsed, 6), 'python_peak_bytes': peak}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--counts', type=int, nargs='+', default=[1000, 5000, 10000])
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 10 or any(not 1 <= count <= 10000 for count in args.counts):
        parser.error('counts must be 1-10000, repeats 1-10')
    results = []
    for count in args.counts:
        content = ('备注 ' + 'gh' + 'p_' + 'A1b2' * 9 + '\n') * count
        blob = content.encode('utf-8')
        # One independent warmup for both implementations; exclude it from timing.
        expected = prefix_reference('synthetic', content)
        assert scan_blob('synthetic', blob) == expected
        samples = {'prefix_reference': [], 'segmented': []}
        for repeat in range(args.repeats):
            # Alternate execution order to reduce systematic first-run bias.
            order = ('prefix_reference', 'segmented') if repeat % 2 == 0 else ('segmented', 'prefix_reference')
            for name in order:
                call = (lambda: prefix_reference('synthetic', content)) if name == 'prefix_reference' else (
                    lambda: scan_blob('synthetic', blob))
                actual, measurement = measure(call)
                assert actual == expected
                samples[name].append(measurement)
                del actual
        results.append({'candidates': count, 'blob_bytes': len(blob), 'samples': samples,
                        'median_seconds': {name: statistics.median(item['seconds'] for item in values)
                                           for name, values in samples.items()}})
    print(json.dumps({'python': platform.python_version(), 'platform': platform.system(),
                      'scope': 'synthetic in-memory blobs, no Git IO or native RSS',
                      'repeats': args.repeats, 'results': results}, indent=2))


if __name__ == '__main__':
    main()
