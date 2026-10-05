# Synthetic rule evaluation v1

Run `python -m secretlens.evaluation --check` (or installed `secretlens-evaluate --check`). Deterministic647 samples:625 supported,22 known-gap. Synthetic values are built at runtime, never genuine credentials. No network/provider/model calls or project-file reads. Truth labels are constructed separately from scan results. This is a small constructed regression corpus, not random sampling or provider validation; its many encoding variants are correlated. Do not extrapolate the percentages to real repositories.

Supported cases cover GitHub legacy prefixes p/o/u/s/r at36/37/255 lengths, fine-grained40/255, invalid lengths and word boundaries; AWS AKIA/ASIA16-character suffixes, invalid length/lowercase;6 private-key markers vs public/certificate;8 assignment spellings at16/512, both quotes vs too short/long, multiline/unquoted/unrelated fields. UTF8,UTF8-BOM,UTF16LE/BE-BOM,UTF32LE/BE-BOM; Unicode line/column, repeated and overlapping findings and binary ASCII. Exact localization/count truth additionally guards a detector which reports the right rule at the wrong place or twice.

Known gaps deliberately label intended synthetic credentials in4 no-BOM wide encodings and escaped JSON per rule (20 samples), one short password (miss) and one benign test placeholder (false positive). These labels define the task, not live credential validity. Counts across all647 samples:

| Rule | TP | FP | FN | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| github-token |109|0|5|533|1.0000|0.9561|
| aws-access-id |18|0|5|624|1.0000|0.7826|
| private-key |36|0|5|606|1.0000|0.8780|
| assigned-secret |198|1|6|442|0.9950|0.9706|

Unit: each rule/sample presence (not each occurrence, not byte accuracy). All625 supported samples have zeroFP/FN and exact occurrence/location matches under current rules.22 gap samples remain mismatches; supported_passed only checks supported regression acceptance. Denominators include every sample even when another rule is its target. No macro averaged accuracy obscuring class balance; undefined precision/recall are null. Scanner exceptions/invalid metadata abort instead of becoming negatives.

corpus_sha25606474dc0e13c398e94c77eba0c6b0d4bc02f60ed1c7149a14bf759025a625d0e binds bytes, truth and cohort in canonical case-ID order. rules_sha256113b9b21a436bb781f9f64bb181414abbff9ad6f8beecdf12ba239480437e3c3 binds regex text, flags and group selection. Hashes identify this synthetic revision, not signatures. Reports do not include candidate values, snippets, per-sample blob hashes or findings fingerprints. Case names are controlled ASCII identifiers. The CLI has no file-input option and only evaluates the built-in synthetic corpus; the Python API accepts explicitly supplied test cases for testing the evaluator.

--check exits0 for supported acceptance,1 for supported location/count regressions,2 for failed evaluation. Known gaps are not silently fixed/ignored. CI reruns source and installed-wheel evaluation. Next: independent larger positive/negative corpus and additional provider coverage; maintain separate current support/known-gap definitions and review label changes rather than fitting truth to detector output.
