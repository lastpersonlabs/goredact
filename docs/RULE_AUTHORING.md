# Rule authoring

Built-in rules are declared in `internal/rules/specs/*.json` and compiled by
`go generate ./internal/rules`. Do not hand-edit the generated `zz_generated_*`
files.

Each rule needs a stable `id`, display `name`, one or more bounded literal
`triggers`, a validator name, minimum profile, confidence, maximum lookbehind
and lookahead, provenance, and both matching and non-matching synthetic
fixtures. Provider documentation is the preferred provenance source. Fixtures
must never be copied from live credentials.

Validators live in `internal/rules/validators`. They operate on byte slices,
must respect the supplied bounded window, must not retain or log source bytes,
and return only a half-open span. Validate prefix, length, alphabet, separators,
boundaries, and placeholders as applicable. A generic prefix requires
additional context or entropy validation; do not promote a heuristic rule into
the fast profile.

After changing a rule:

```sh
go generate ./internal/rules
go generate ./internal/accuracy
gofmt -w internal/rules
go test ./...
go test -race ./...
```

Update `docs/PROFILES.md` when rule metadata changes. The generated accuracy
corpus requires positive and negative coverage for every built-in rule and
tests fixtures across chunk boundaries. When a rule overlaps Gitleaks semantics,
add it to the deliberately supported offline differential subset and compare
only sanitized aggregate results.

Embedding applications that need private rules should prefer `Config.CustomRules`
instead of editing generated built-ins. Custom validators have the same bounded
window and no-source-logging obligations.
