# goredact

[![CI](https://github.com/lastpersonlabs/goredact/actions/workflows/ci.yml/badge.svg)](https://github.com/lastpersonlabs/goredact/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/lastpersonlabs/goredact.svg)](https://pkg.go.dev/github.com/lastpersonlabs/goredact)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`goredact` is a pure-Go, bounded-memory library for detecting and redacting
secrets in large byte streams. It is designed for agent sessions, logs,
environment dumps, and upload pipelines where plaintext temporary files are
not acceptable.

## Motivation

Secret detection often sits directly in the path of high-volume agent output,
logs, and uploads. A scanner that cannot keep up either becomes a bottleneck or
forces applications to buffer sensitive data. GoRedact is built to make that
trade-off unnecessary: it scans and redacts in one pass with bounded memory.

On a reproducible, one-core scan of the same deterministic 512 MiB quiet-log
corpus, GoRedact's balanced profile delivered:

| Compared with | Speed gain | GoRedact throughput | Other-tool throughput |
| --- | ---: | ---: | ---: |
| Gitleaks 8.30.1-1 | **97.6x faster** | 701.37 MiB/s | 7.19 MiB/s |
| Betterleaks 1.7.4 | **6.2x faster** | 701.37 MiB/s | 113.27 MiB/s |

The advantage also held on a private, candidate-heavy corpus of 976 real
Codex and Claude session files (627.95 MiB). In a local single-core run,
GoRedact completed in 0.99 seconds (634.29 MiB/s), versus 27.47 seconds for
Betterleaks (22.86 MiB/s), making GoRedact **27.8x faster** by median wall
time. Gitleaks did not complete one pass within three minutes, so GoRedact was
at least **181x faster** at that cutoff. This local run was subject to sandbox
CPU throttling and is supporting evidence rather than a dedicated-host release
benchmark.

These results measure baseline scanning throughput on that workload, not
relative recall or precision; the tools use different rule sets and behavior.
See the full [benchmark protocol and results](docs/BENCHMARKS.md), including
versions, raw wall and CPU times, memory use, host details, session-corpus
selection, scanner flags, limitations, and reproduction commands.

```go
engine, err := goredact.New(goredact.Config{
	Profile: goredact.ProfileBalanced,
})
if err != nil {
	log.Fatal(err)
}

stats, err := engine.Redact(ctx, os.Stdout, os.Stdin)
if err != nil {
	log.Fatal(err)
}
log.Printf("redactions=%d bytes=%d", stats.Findings, stats.BytesRead)
```

The zero configuration selects the balanced profile. An engine is immutable
after construction and safe for concurrent use; every call consumes an
`io.Reader` and writes redacted bytes to an `io.Writer` without retaining the
whole input.

By default each secret is replaced with one `[REDACTED]` marker
(`Config.Marker`). `Config.MaskStrategy` can instead select
`MaskLengthPreserving` (`*` per redacted byte, output length equals input
length) or `MaskFormatPreserving` (per-character-class substitution that
also keeps separators, so token shapes and fixed-width records survive) —
see the `MaskStrategy` docs for the disclosure trade-offs.

## Install and use

```sh
go get github.com/lastpersonlabs/goredact@v0.1.0
go install github.com/lastpersonlabs/goredact/cmd/goredact@v0.1.0
goredact stream --profile balanced < session.jsonl > session.redacted.jsonl
goredact stream --zstd --stats - < session.jsonl > session.redacted.jsonl.zst
goredact dir --report-format sarif --report-path findings.sarif ./workspace
```

Run `goredact --help` to discover commands, `goredact <command> --help` for
command-specific flags and examples, or `goredact completion --help` to set up
shell completion. The `stream` command also accepts `--input` and `--output`; it removes incomplete
output after a failed scan. The `dir` command recursively scans regular files
and writes JSON, CSV, JUnit, or SARIF findings without including matched secret
values. By default, progress, statistics, and reports contain metadata and
counts only. See
[`docs/CLI_AND_UPLOAD.md`](docs/CLI_AND_UPLOAD.md) for reports, compression, and
multipart upload integration.

Directory reports omit matched values by default. `dir --show-secrets` includes
them when explicitly requested; its output must be handled as credential
material.

## Detection and guarantees

The built-in rules cover provider tokens (source control, cloud, AI, payment,
messaging, and project management), authentication headers, contextual
assignments, cookies, credentials in URLs, and private-key blocks. Fast,
balanced, and deep profiles trade detector coverage for cost; deep adds a
broader-keyword, lower-confidence generic assignment heuristic on top of
everything balanced already catches. See [`docs/PROFILES.md`](docs/PROFILES.md)
for the complete rule table.

For every profile, memory is bounded by the configured chunk and rule windows.
Matched bytes are excluded from findings, statistics, and package-generated
errors. The same input, rule-set version, and configuration produce the same
output. Detection is deliberately not a proof that an input contains no
secrets; unsupported encodings and obfuscation are documented in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Development and release evidence

```sh
go test ./...
go test -race ./...
go vet ./...
make bench-ci
```

- Architecture: [`docs/DESIGN.md`](docs/DESIGN.md)
- Accuracy and differential harness: [`docs/ACCURACY.md`](docs/ACCURACY.md)
- Benchmark suite and report procedure: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
- Rule authoring: [`docs/RULE_AUTHORING.md`](docs/RULE_AUTHORING.md)
- Security reporting: [`SECURITY.md`](SECURITY.md)
- Versioning: [`docs/VERSIONING.md`](docs/VERSIONING.md)
- Changes: [`CHANGELOG.md`](CHANGELOG.md)
- Code of Conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

The core library remains stdlib-only and has no cgo path. The optional
reference CLI uses the pure-Go `klauspost/compress` module for zstd.

## Licence

MIT. Dependency and source provenance is recorded in [`THIRD_PARTY.md`](THIRD_PARTY.md).
