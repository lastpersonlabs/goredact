# Accuracy corpus

`internal/accuracy` is a reusable synthetic corpus generated from the canonical
positive and negative fixtures in `internal/rules/specs`. It covers every
built-in rule and labels agent JSON/JSONL, shell, diff, environment, HTTP,
minified, escaped, and keyword-adversarial forms. `go generate
./internal/accuracy` refreshes it after a rule fixture changes.

`TestCorpusAccuracyByRuleAndProfile` reports recall and false-positive counts
for every rule under fast, balanced, and deep profiles. Each fixture is scanned
at the start of input and on both sides of a real 64 KiB chunk boundary. Test
failures contain only rule IDs, format labels, ordinals, and aggregate counts;
fixture values and redacted output must never appear in CI logs.

The optional scanner differentials are offline oracles against Gitleaks and
[Betterleaks](https://github.com/betterleaks/betterleaks), its successor from
the same authors. Install or provide pinned binaries, then select only rules
whose semantics intentionally overlap:

```sh
GITLEAKS_BIN=/path/to/gitleaks \
GOREDACT_GITLEAKS_RULES=gitlab-pat \
go test ./internal/accuracy -run TestGitleaksDifferential -v

BETTERLEAKS_BIN=/path/to/betterleaks \
GOREDACT_BETTERLEAKS_RULES=gitlab-pat \
go test ./internal/accuracy -run TestBetterleaksDifferential -v
```

The harness never downloads tools and suppresses scanner output because it may
contain matched text. Its JSON report lives in the test's private temporary
directory and is used only to compute sanitized per-rule metrics.

## v0.1.0 release run

On 2026-08-14, the generated 304-fixture matrix passed for fast, balanced,
and deep profiles across all three placements. All negative fixtures reported
zero same-rule false positives. The report deliberately exposes partial recall
for conservative or boundary-sensitive shapes instead of turning the corpus
into a claim of perfect detection; see the threat model before treating output
as a completeness guarantee.

The Gitleaks comparison passed during v0.1.0 release verification for the exact-overlap
`gitlab-pat` subset: recall was 2/2 with 0/3 false positives. `github-pat` is
not in the exact subset because goredact deliberately rejects repeated-character
placeholder tokens while Gitleaks reports that shape. A compatibility run found
both real-shape GitHub fixtures and also reported one such placeholder.
Keeping the subset explicit prevents a difference in documented placeholder
policy from being misreported as a detector regression.

The Betterleaks 1.7.4 differential passed on 2026-08-14 for the same
exact-overlap `gitlab-pat` subset: recall was 2/2 with 0/3 false positives.
Betterleaks inherits Gitleaks' placeholder behavior: a `github-pat`
compatibility run found all twelve real-shape fixtures and also reported the
repeated-character placeholder, so `github-pat` stays outside the exact subset
for both scanners.

## SecretBench evaluation

`tools/secretbench` measures candidate-level precision, recall, and F1 against
the independently labeled [SecretBench](https://github.com/setu1421/SecretBench)
corpus. SecretBench's repository is public, but its labels and source files are
access-controlled because they contain historical credentials. Obtain access
from the dataset authors and accept its data-protection agreement before using
the harness. The tool does not download the corpus.

After access is granted, export the BigQuery table and extract `Files.zip` into
the ignored `.secretbench` directory:

```sh
mkdir -p .secretbench/files
bq query --use_legacy_sql=false --format=json \
  'SELECT * FROM `dev-range-332204.secretbench.secrets` ORDER BY id' \
  > .secretbench/annotations.json
gcloud storage cp gs://secretbench/Files.zip .secretbench/Files.zip
unzip .secretbench/Files.zip -d .secretbench/files
```

Run the public-comparability and product-policy views separately:

```sh
make accuracy-secretbench ARGS='-annotations .secretbench/annotations.json \
  -files .secretbench/files -policy full -format json \
  -output .secretbench/full.json'

make accuracy-secretbench ARGS='-annotations .secretbench/annotations.json \
  -files .secretbench/files -policy goredact -format markdown \
  -output .secretbench/goredact.md'
```

`full` scores all eight SecretBench categories for comparison with other
tools. `goredact` excludes `Username` and the mixed `Other` category because
those categories include identifiers that this library does not claim to
redact. Reports contain micro totals, macro averages, per-category metrics,
the rule-set version, and SHA-256 hashes of the annotation export and scanned
corpus. They never include the dataset's `secret` field or matched bytes.

SecretBench does not document whether columns are zero- or one-based or whether
the end column is inclusive. The defaults are zero-based and inclusive; verify
them against the supplied files, then use `-column-base 1` or
`-end-inclusive=false` when required. Columns are interpreted as byte offsets.

The dataset labels regex-mined candidates rather than every byte span in each
file. Therefore a true-labeled detected candidate is a true positive, a
false-labeled detected candidate is a false positive, and an unmatched
goredact finding is reported separately as `unmatched_findings`. Treating such
unlabeled findings as false positives would understate precision without manual
adjudication. Reports should be described as SecretBench candidate-level
metrics, not as deployment-wide alert precision.
