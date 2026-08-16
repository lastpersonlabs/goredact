# Changelog

All notable changes are documented here. This project follows semantic
versioning.

## v0.1.0 — 2026-08-16

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
- Reference CLI with stream and recursive directory commands, optional secret
  display in JSON/CSV/JUnit/SARIF reports, streaming zstd, and a bounded
  multipart-upload example. Directory scans emit a count-only findings summary
  on standard error.
- Cobra-based CLI with discoverable command and flag help, conventional long
  and shorthand flags, version output, typo suggestions, examples, argument
  validation, and generated shell completion.
- Add a standalone JWT detection rule (`jwt`, balanced profile): bare
  `header.payload.signature` JWS compact serializations in transcripts,
  logs, and tool output are now caught without needing cookie or header
  context.
- Add `Config.MaskStrategy` with `MaskFixedMarker` (default, unchanged
  behavior), `MaskLengthPreserving` (`*` fill, output length equals input
  length), and `MaskFormatPreserving` (per-character-class substitution
  that keeps token shapes), plus a `--mask` flag on `goredact stream`.
- Detect `session_secret` and `secret_key_base` assignment families.
- Make directory scans parallel and deterministic while reusing compiled
  engines across files.
- Apply Gitleaks-compatible default dependency, generated-file, media, and
  binary path exclusions during recursive directory scans.
- `scripts/benchmark-betterleaks.zsh` takes an optional GoRedact profile
  argument; `docs/BENCHMARKS.md` adds a cross-profile (`fast`/`balanced`/`deep`)
  one-core comparison against Betterleaks.
- Public API types (`Config`, `Engine`, `Finding`, `Stats`, `RuleInfo`,
  `Profile`, `Confidence`, `MaskStrategy`, `ReadError`, `WriteError`) are no
  longer bare aliases into the internal implementation package, so
  `go doc`/pkg.go.dev now render their field and method documentation.
- `Stats.Findings` is `int64` and `Stats.ByRule`'s values are `int64`,
  matching the other counters on `Stats`.
- Fixed several validator inconsistencies found in a pre-publish review:
  `SlackUserToken` now rejects placeholder digit segments like
  `SlackBotToken` already did; `DopplerToken`'s optional config-label
  grammar is scoped to the `dp.st.` prefix that actually documents one,
  instead of over-matching all seven scoped prefixes; every
  fixed-literal-prefix token rule (GitHub, GitLab, npm, PyPI, Docker Hub,
  Stripe, Vault, Vercel, Doppler) now rejects a trigger embedded inside a
  longer identifier or blob, matching the convention already used by
  AWS/GCP/Hugging Face/Groq/OpenAI/Cursor rules.

Release evidence and known detection limits are documented in `docs/ACCURACY.md`,
`docs/BENCHMARKS.md`, and `docs/THREAT_MODEL.md`.
