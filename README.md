# goredact

`goredact` is a pure-Go, bounded-memory library for detecting and redacting
secrets in large byte streams. It is designed for agent sessions, logs,
environment dumps, and upload pipelines where plaintext temporary files are
not acceptable.

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

## Install and use

```sh
go get github.com/lastpersonlabs/goredact@v0.1.0
go install github.com/lastpersonlabs/goredact/cmd/goredact@v0.1.0
goredact stream -profile balanced < session.jsonl > session.redacted.jsonl
goredact stream -zstd -stats - < session.jsonl > session.redacted.jsonl.zst
goredact dir -report-format sarif -report-path findings.sarif ./workspace
```

The `stream` command also accepts `-input` and `-output`; it removes incomplete
output after a failed scan. The `dir` command recursively scans regular files
and writes JSON, CSV, JUnit, or SARIF findings without including matched secret
values. Progress, statistics, and reports contain metadata and counts only. See
[`docs/CLI_AND_UPLOAD.md`](docs/CLI_AND_UPLOAD.md) for reports, compression, and
multipart upload integration.

## Detection and guarantees

The built-in rules cover provider tokens (source control, cloud, AI, payment,
messaging, and project management), authentication headers, contextual
assignments, cookies, credentials in URLs, and private-key blocks. Fast,
balanced, and deep profiles trade detector coverage for cost; deep currently
selects the same rules as balanced in v0.1. See [`docs/PROFILES.md`](docs/PROFILES.md)
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

The core library remains stdlib-only and has no cgo path. The optional
reference CLI uses the pure-Go `klauspost/compress` module for zstd.

## Licence

MIT. Dependency and source provenance is recorded in [`THIRD_PARTY.md`](THIRD_PARTY.md).
