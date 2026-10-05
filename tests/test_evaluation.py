from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from secretlens.core import ScanError
from secretlens.evaluation import Case, Expected, RULE_NAMES, corpus, evaluate, main


class EvaluationTests(unittest.TestCase):
    def test_supported_truth_and_known_gaps_are_both_visible(self):
        report = evaluate()
        self.assertTrue(report['supported_passed'])
        self.assertEqual(report['samples'], 647)
        self.assertEqual(report['cohorts']['supported'], 625)
        self.assertEqual(report['cohorts']['known-gap'], 22)
        self.assertEqual(report['corpus_sha256'], '06474dc0e13c398e94c77eba0c6b0d4bc02f60ed1c7149a14bf759025a625d0e')
        expected_overall = {'github-token': (109, 0, 5, 533), 'aws-access-id': (18, 0, 5, 624),
                            'private-key': (36, 0, 5, 606), 'assigned-secret': (198, 1, 6, 442)}
        for rule, values in expected_overall.items():
            self.assertEqual(tuple(report['metrics']['overall'][rule][k] for k in ('tp', 'fp', 'fn', 'tn')), values)
        for rule in RULE_NAMES:
            supported = report['metrics']['supported'][rule]
            self.assertEqual((supported['fp'], supported['fn']), (0, 0))
            self.assertGreater(supported['tp'], 0)
            self.assertGreater(supported['tn'], 0)
            self.assertGreater(report['metrics']['known-gap'][rule]['fn'], 0)
        self.assertEqual(report['metrics']['known-gap']['assigned-secret']['fp'], 1)
        self.assertTrue(all(m['cohort'] == 'known-gap' for m in report['localization_and_count_mismatches']))

    def test_report_deterministic_order_independent_and_no_sample_content(self):
        cases = corpus()
        first = evaluate(cases)
        self.assertEqual(first, evaluate(reversed(cases)))
        rendered = json.dumps(first, sort_keys=True)
        self.assertNotIn('gh' + 'p_' + 'A1b2' * 9, rendered)
        self.assertNotIn('example-' * 3, rendered)
        self.assertNotIn('V' * 16, rendered)
        self.assertNotIn('fingerprint', rendered)
        self.assertNotIn('blob_sha256', rendered)
        self.assertEqual(len(first['corpus_sha256']), 64)

    def test_independent_confusion_oracle_for_missed_and_false_positive_samples(self):
        cases = (Case('true', 'supported', b'x', (Expected('github-token', 1, 1),)),
                 Case('benign', 'supported', b'y', ()))
        def mutated(path, blob):
            return [] if blob == b'x' else [{'rule': 'github-token', 'line': 1, 'column': 1}]
        report = evaluate(cases, scanner=mutated)
        self.assertFalse(report['supported_passed'])
        self.assertEqual(report['metrics']['overall']['github-token'],
                         {'tp': 0, 'fp': 1, 'fn': 1, 'tn': 0, 'precision': 0.0, 'recall': 0.0})

    def test_localization_and_duplicates_fail_even_with_perfect_presence_metrics(self):
        cases = (Case('location', 'supported', b'x', (Expected('github-token', 2, 3),)),)
        for actual in ([{'rule': 'github-token', 'line': 2, 'column': 4}],
                       [{'rule': 'github-token', 'line': 2, 'column': 3}] * 2):
            report = evaluate(cases, scanner=lambda p, b: actual)
            self.assertFalse(report['supported_passed'])
            self.assertEqual(report['metrics']['overall']['github-token']['tp'], 1)
            self.assertGreater(report['localization_and_count_mismatches'][0]['unexpected_occurrences'], 0)

    def test_denominators_preserve_all_cases_and_null_metrics_are_not_perfection(self):
        report = evaluate((Case('negative', 'known-gap', b'', ()),))
        for rule in RULE_NAMES:
            counts = report['metrics']['overall'][rule]
            self.assertIsNone(counts['precision'])
            self.assertIsNone(counts['recall'])
            self.assertEqual(counts['tn'], 1)
        report = evaluate()
        for cohort, samples in {**report['cohorts'], 'overall': report['samples']}.items():
            for rule in RULE_NAMES:
                counts = report['metrics'][cohort][rule]
                self.assertEqual(sum(counts[k] for k in ('tp', 'fp', 'fn', 'tn')), samples)

    def test_digest_binds_truth_bytes_and_cohort(self):
        original = Case('sample', 'supported', b'x', ())
        digest = evaluate((original,))['corpus_sha256']
        for other in (Case('sample', 'supported', b'y', ()), Case('sample', 'known-gap', b'x', ()),
                      Case('sample', 'supported', b'x', (Expected('github-token', 1, 1),))):
            self.assertNotEqual(digest, evaluate((other,))['corpus_sha256'])

    def test_invalid_inputs_or_scanner_failures_are_not_counted_as_negatives(self):
        valid = Case('valid', 'supported', b'', ())
        for cases in ((), (valid, valid), (Case('../path', 'supported', b'', ()),),
                      (Case('bad', 'hidden', b'', ()),), (Case(123, 'supported', b'', ()),),
                      (Case('bad', 'supported', b'', None),),
                      (Case('bad', 'supported', b'', (Expected('github-token', 1, 1),) * 2),),
                      (Case('bad', 'supported', b'', (Expected('unknown', 1, 1),)),)):
            with self.subTest(cases=cases), self.assertRaises(ScanError):
                evaluate(cases)
        for bad in ([{'rule': 'unknown', 'line': 1, 'column': 1}],
                    [{'rule': 'github-token', 'line': True, 'column': 1}], [{}], None):
            with self.subTest(bad=bad), self.assertRaises(ScanError):
                evaluate((valid,), scanner=lambda p, b: bad)

    def test_cli_check_exit_codes_and_non_disclosing_failure(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(['--check']), 0)
        self.assertTrue(json.loads(output.getvalue())['supported_passed'])
        with patch('secretlens.evaluation.evaluate', return_value={'supported_passed': False}), redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--check']), 1)
            self.assertEqual(main([]), 0)
        output = io.StringIO()
        with patch('secretlens.evaluation.evaluate', side_effect=ScanError('sensitive diagnostic')), redirect_stdout(output):
            self.assertEqual(main(['--check']), 2)
        self.assertNotIn('sensitive diagnostic', output.getvalue())


if __name__ == '__main__':
    unittest.main()
