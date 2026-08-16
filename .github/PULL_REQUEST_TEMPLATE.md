## What changed

<!-- Summarize the change. If a package contract from docs/DESIGN.md
changed, say so explicitly. -->

## Why

<!-- The motivation: bug being fixed, gap being closed, etc. -->

## How this was tested

<!-- Which of the following did you run? -->

- [ ] `go build ./...`
- [ ] `go vet ./...`
- [ ] `go test -race ./...`
- [ ] `make lint` (gofmt + vet + staticcheck)
- [ ] Fuzz smoke pass on any changed parsing/matching/span/streaming code
- [ ] `go generate ./internal/rules` (if a rule spec changed) and fixtures
      regenerated

## Checklist

- [ ] No real, live secret values appear anywhere in this PR (description,
      diff, commit messages, or CI logs) — only synthetic/placeholder
      values, per `CONTRIBUTING.md` and `SECURITY.md`.
- [ ] New or adapted third-party code is recorded in `THIRD_PARTY.md`
      (see `CONTRIBUTING.md`), or this PR doesn't add any.
- [ ] `docs/PROFILES.md` / `docs/DESIGN.md` updated if rule metadata or a
      package contract changed.
