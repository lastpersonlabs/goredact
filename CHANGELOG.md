# Changelog

All notable changes are documented here. This project follows semantic
versioning.

## v0.1.0 — 2026-08-14

Initial release.

- Bounded-memory `io.Reader` to `io.Writer` redaction API with deterministic
  span merging, cancellation, typed I/O errors, and record-aligned streaming.
- Fast, balanced, and deep profiles; rule introspection, allow/deny lists, and
  custom validators.
- Deterministic provider, contextual credential, entropy, URL/header/cookie,
  and multiline private-key detection.
- Generated rule schema with provenance and synthetic fixtures.
- Accuracy corpus, sanitized offline Gitleaks differential harness, fuzz and
  property tests, and reproducible large-corpus benchmark tooling.
- Reference CLI with streaming zstd and a bounded multipart-upload example.

Release evidence and known detection limits are documented in `docs/ACCURACY.md`,
`docs/BENCHMARKS.md`, and `docs/THREAT_MODEL.md`.
