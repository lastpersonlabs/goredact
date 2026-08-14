# Contributing to goredact

Thanks for contributing. goredact is a pure-Go, stdlib-only core library that
redacts secrets from streams; because of what it handles, correctness and
"never leak a secret value" are held to a higher bar than typical hygiene.
Please read `docs/DESIGN.md` and `docs/THREAT_MODEL.md` before making
non-trivial changes — they freeze the internal contracts between packages
and the security guarantees this library makes.

## Building and testing

The module has zero external dependencies and requires no cgo. Standard Go
tooling is all you need:

```sh
go build ./...
go vet ./...
go test ./...
```

### Race detector

Concurrency correctness (an immutable `Engine`/`Automaton` used safely across
goroutines) is a hard requirement. Always run the race detector before
sending a PR:

```sh
go test -race ./...
```

### Fuzz smoke

Fuzz targets (`Fuzz*` functions in `*_fuzz_test.go` files) encode the
cross-cutting invariants in `docs/DESIGN.md` (no panics on any byte
sequence, confirmed spans never leak, chunking-independence, etc.). Before
sending a PR touching parsing, matching, span handling, or the streaming
engine, run a short fuzz smoke pass on the affected package(s):

```sh
go test -run '^$' -fuzz '^FuzzYourTarget$' -fuzztime 10s ./path/to/pkg
```

or use the discovery loop wired into CI/`make fuzz-smoke`, which runs every
`Fuzz*` target it finds for a short `-fuzztime`. If you find a crasher, the
minimized failing input is written under `testdata/fuzz/...` — check it in.

### Benchmarks

Benchmarks report throughput via `b.SetBytes`. They don't need to run to
completion locally on every change, but they must at least compile and run
once (`make bench` or `go test -bench . -benchtime 1x ./...`), which CI also
enforces.

## Coding conventions

- **Stdlib-only core.** The library itself (module root and `internal/`) must
  not import external dependencies. Reference commands and integrations may
  use reviewed pure-Go dependencies; record them in `THIRD_PARTY.md`.
- **No cgo.** `CGO_ENABLED=0` must keep working.
- **No allocation proportional to input size** in the streaming path;
  memory usage must stay bounded regardless of input size (see
  `docs/DESIGN.md` for the buffering contract).
- **Table-driven tests.** Prefer `[]struct{ name string; ... }` cases run in
  a loop (with `t.Run` subtests) over repeated near-identical test
  functions.
- **Never put secret values in errors, logs, or diagnostics.** Errors,
  findings, and any log-like output must only carry rule IDs, offsets, and
  counts — never matched input bytes. This is enforced by tests and review;
  see `docs/THREAT_MODEL.md` ("No secret leakage through diagnostics") for
  the exact guarantee. When writing test fixtures with realistic-looking
  secrets, use synthetic/clearly-fake values.
- **Panic-free on arbitrary input.** Any byte sequence, including invalid
  UTF-8 and arbitrary binary, must be handled without panicking.
- Keep package boundaries and contracts as specified in `docs/DESIGN.md`;
  if a change requires altering a frozen contract between packages, call
  that out explicitly in the PR description.

## Contributing detection rules

Built-in detection rules are **generated**, not hand-written directly into
`internal/rules`. `internal/rules` defines the shared vocabulary
(`Rule`, `Trigger`, `ValidateFunc`, `Set`, `Build`) and built-in tables are
registered via `RegisterBuiltins` from an `init` in a generated file inside
that package. If you're adding or updating a built-in rule:

- Look at the existing generator/source-of-truth for rule tables under
  `internal/rules` before hand-editing generated output.
- Don't hand-edit generated files directly; change the generator input and
  regenerate, so the generated file stays reproducible.
- New rules need: a trigger pattern, a bounded-window validator, test
  fixtures covering true positives/negatives and chunk-boundary splits, and
  (if the rule is highly variable in structure) fuzz coverage.
- Custom, non-built-in rules supplied by API callers follow the public
  `Rule`/`ValidateFunc` contract in `goredact.go`/`internal/rules` and don't
  need to go through generation.

## Vendored or adapted code

If you bring in code adapted or copied from another project (even a small
snippet), it must be recorded in `THIRD_PARTY.md` with source URL, upstream
commit, licence, and local path, **before** the PR merges. PRs that add
copied code without a corresponding `THIRD_PARTY.md` entry will be asked to
add one; CI's `licence-check` job also greps for stray third-party copyright
headers as a backstop.

## Commit and PR conventions

- Keep commits focused; prefer several small, reviewable commits over one
  large one when a change has logically separate parts.
- Write commit subject lines in the imperative mood ("Add X", "Fix Y", not
  "Added"/"Fixes"), under ~70 characters, with a body explaining *why* when
  the change isn't self-evident.
- Reference the relevant issue (e.g. `ENG-123`) in the PR description.
- PRs should describe: what changed, why, and how it was tested (which of
  the commands above were run). If a package contract from
  `docs/DESIGN.md` changed, say so explicitly.
- All CI checks (`test`, `lint`, `fuzz-smoke`, `bench-compile`,
  `licence-check`) must pass before merge.
