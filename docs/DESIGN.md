# Architecture — goredact

This document describes the package architecture and the invariants that
contributors must preserve. Public API documentation lives in `api.go` and
`doc.go`.

## Data flow

```
io.Reader → [chunked buffer] → Aho–Corasick matcher → trigger hits
    → rule validators (bounded windows) → confirmed spans
    → span collector (dedupe/merge/precedence) → redacting emitter → io.Writer
```

## Packages

### `internal/rules`

`Rule`, `Trigger`, `ValidateFunc`, `Set`, `Build`. Generated built-in
tables call `RegisterBuiltins` from an `init` in a generated file inside
this package. `Set.MaxWindow()` is the overlap the engine must retain.

### `internal/ahocorasick`

Pure-Go Aho–Corasick over bytes. Contract:

```go
type Pattern struct {
    Literal  string // non-empty
    CaseFold bool   // ASCII case-insensitive match
}

func Compile(patterns []Pattern) (*Automaton, error)

// State carries matcher position across chunk boundaries. Zero value =
// automaton root (start state).
type State uint32

// Scan advances through chunk, invoking fn for every pattern occurrence
// (including overlapping ones) with the pattern index (into the Compile
// slice) and the exclusive end offset of the match within chunk. A match
// that started in a previous chunk reports end < pattern length; the
// caller reconstructs absolute offsets. fn returning false stops the scan
// early. Scan performs no heap allocation.
func (a *Automaton) Scan(s State, chunk []byte, fn func(pattern int, end int) bool) State
```

- Automaton is immutable after Compile; concurrent Scans are race-free.
- Case folding: fold both pattern and input bytes 'A'..'Z' → 'a'..'z' for
  CaseFold patterns; case-sensitive patterns must still match exactly
  (build the automaton over folded bytes with post-check, or dual-plane
  goto — implementation's choice, as long as both semantics hold).
- Overlapping matches via output links (dictionary suffix links).

### `internal/span`

Confirmed-span collection, merge, precedence, ordered release.

```go
type Span struct {
    Start, End int64 // absolute input offsets, half-open
    Rule       int   // index into the active rule set
    Confidence uint8
}

// Collector accumulates spans out of order and releases them in order.
type Collector struct{ ... }

func (c *Collector) Add(s Span)             // dedupes identical spans
// Release appends to dst all merged spans that end at or before limit and
// cannot grow further, removing them from the collector. Returned spans
// are sorted by Start and non-overlapping.
func (c *Collector) Release(dst []Span, limit int64) []Span
func (c *Collector) Pending() bool
func (c *Collector) Reset()
```

Merge/precedence rules (deterministic):
1. Identical spans (same Start/End) dedupe; keep highest Confidence, then
   lowest Rule index.
2. Overlapping or adjacent (End == Start) spans merge into their union;
   attribution goes to the higher-Confidence span, tie → earlier Start,
   tie → lower Rule index.
3. Released output is sorted by Start; no two released spans overlap.

### `internal/goredact`

Implements the streaming loop and the engine exposed through aliases and
constructors in the module-root package.

Requirements:
- Fixed ring/sliding buffer of ChunkSize + MaxWindow overlap.
- Trigger hits whose lookahead window is not yet fully buffered are
  deferred until more input arrives or EOF.
- Emission frontier: bytes may be written once `pos + MaxWindow` has been
  read (or EOF), after applying released spans; marker replaces each span.
- Context checked between chunks. Reader errors → *ReadError, writer
  errors → *WriteError, ctx.Err() preserved.
- No temporary files. No allocation proportional to input size.

## Cross-cutting invariants (enforced by tests/fuzz)

1. Confirmed span bytes never appear in output.
2. Output equals input outside redacted spans.
3. Chunked and unchunked scans of the same input are byte-identical.
4. Same input+config → same output (chunk-size independence).
5. Errors/log strings never embed input bytes.
6. Any byte sequence is safe: no panics, bounded memory.

## Conventions

- Zero external dependencies (stdlib only) for the library.
- Table-driven tests; fuzz targets under `*_fuzz_test.go` with `FuzzXxx`.
- Benchmarks report MB/s via `b.SetBytes`.
