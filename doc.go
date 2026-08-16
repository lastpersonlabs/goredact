// Package goredact provides high-throughput streaming detection and
// redaction of secrets from large text streams such as agent session logs,
// build output, and environment dumps.
//
// The library is pure Go (no cgo) and processes input through fixed-size
// buffers, so memory usage is bounded regardless of input size. Input is
// consumed from an io.Reader and redacted output is written to an io.Writer;
// no temporary files are ever created.
//
// # Guarantees
//
//   - Bounded memory: memory usage does not grow with input size.
//   - No plaintext persistence: unredacted data is never written to
//     temporary storage.
//   - No secret leakage: matched secret values never appear in errors,
//     findings, statistics, or any diagnostic output produced by this
//     package.
//   - Determinism: the same input, configuration, and rule-set version
//     always produce identical output.
//   - Reuse: an Engine is immutable after construction and safe for
//     concurrent use across goroutines; each Redact call maintains its own
//     scan state.
//
// # Errors
//
// Errors returned by this package never contain bytes from the scanned
// input. Errors that originate in the caller-supplied reader or writer are
// wrapped in [ReadError] or [WriteError] respectively, so callers can
// distinguish I/O failures from configuration or internal failures; the
// wrapped error is produced by the caller's own io implementation and is
// returned unmodified. Invalid configurations are reported by [New] as
// errors wrapping [ErrInvalidConfig].
//
// # Out of scope for v0.1
//
//   - General-purpose PII detection.
//   - Live credential verification against provider APIs.
//   - Recursive decoding of arbitrary encoded or compressed content
//     (base64-wrapped secrets, custom obfuscation, encrypted payloads).
//   - Detection of secrets split across multiple encodings or interleaved
//     streams.
//
// See docs/THREAT_MODEL.md for the complete threat model.
package goredact
