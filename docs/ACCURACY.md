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

The optional Gitleaks differential is offline: install or provide a pinned
`gitleaks` binary, then select only rules whose semantics intentionally overlap:

```sh
GITLEAKS_BIN=/path/to/gitleaks \
GOREDACT_GITLEAKS_RULES=gitlab-pat \
go test ./internal/accuracy -run TestGitleaksDifferential -v
```

The harness never downloads tools and suppresses scanner output because it may
contain matched text. Its JSON report lives in the test's private temporary
directory and is used only to compute sanitized per-rule metrics.

## v0.1.0 release run

On 2026-08-14, the generated 265-fixture matrix passed for fast, balanced,
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
