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
GOREDACT_GITLEAKS_RULES=github-pat,gitlab-pat \
go test ./internal/accuracy -run TestGitleaksDifferential -v
```

The harness never downloads tools and suppresses scanner output because it may
contain matched text. Its JSON report lives in the test's private temporary
directory and is used only to compute sanitized per-rule metrics.
