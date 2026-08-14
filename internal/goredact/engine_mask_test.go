package goredact

import (
	"errors"
	"strings"
	"testing"
)

// TestMaskStrategyLengthPreserving verifies that MaskLengthPreserving
// yields output of exactly the input's length, with the secret replaced by
// '*' and all other bytes intact.
func TestMaskStrategyLengthPreserving(t *testing.T) {
	e := mustEngine(t, Config{MaskStrategy: MaskLengthPreserving})

	input := "before " + testGHToken + " after"
	out, stats := redactAll(t, e, strings.NewReader(input))

	want := "before " + strings.Repeat("*", len(testGHToken)) + " after"
	if out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	if int64(len(out)) != stats.BytesRead {
		t.Fatalf("output length %d != input length %d", len(out), stats.BytesRead)
	}
	if stats.RedactedBytes != int64(len(testGHToken)) {
		t.Fatalf("RedactedBytes = %d, want %d", stats.RedactedBytes, len(testGHToken))
	}
}

// TestMaskStrategyFormatPreserving verifies per-class substitution: the
// token's letters, digits, and separators keep their classes, and output
// length equals input length.
func TestMaskStrategyFormatPreserving(t *testing.T) {
	e := mustEngine(t, Config{MaskStrategy: MaskFormatPreserving})

	input := "token: " + testGHToken + "\n"
	out, _ := redactAll(t, e, strings.NewReader(input))

	if len(out) != len(input) {
		t.Fatalf("output length %d != input length %d", len(out), len(input))
	}
	if strings.Contains(out, testGHToken) {
		t.Fatal("secret survived format-preserving masking")
	}
	masked := strings.TrimSuffix(strings.TrimPrefix(out, "token: "), "\n")
	if len(masked) != len(testGHToken) {
		t.Fatalf("masked token length %d, want %d", len(masked), len(testGHToken))
	}
	for i := range len(testGHToken) {
		orig, got := testGHToken[i], masked[i]
		var want byte
		switch {
		case orig >= 'A' && orig <= 'Z':
			want = 'X'
		case orig >= 'a' && orig <= 'z':
			want = 'x'
		case orig >= '0' && orig <= '9':
			want = '9'
		case orig == '_':
			want = '_'
		default:
			want = '*'
		}
		if got != want {
			t.Fatalf("byte %d: original class %q masked to %q, want %q", i, orig, got, want)
		}
	}
}

// TestMaskStrategyDoesNotChangeDetection verifies masking only changes
// replacement bytes: findings, counts, and redacted-byte totals are
// identical across strategies, and output outside the span is untouched.
func TestMaskStrategyDoesNotChangeDetection(t *testing.T) {
	input := "a=" + testGHToken + " b=" + testSlackToken + " done"

	var ref Stats
	for i, strategy := range []MaskStrategy{MaskFixedMarker, MaskLengthPreserving, MaskFormatPreserving} {
		e := mustEngine(t, Config{MaskStrategy: strategy})
		out, stats := redactAll(t, e, strings.NewReader(input))
		if strings.Contains(out, testGHToken) || strings.Contains(out, testSlackToken) {
			t.Fatalf("strategy %v: secret survived", strategy)
		}
		if i == 0 {
			ref = stats
			continue
		}
		if stats.Findings != ref.Findings || stats.RedactedBytes != ref.RedactedBytes || stats.Candidates != ref.Candidates {
			t.Fatalf("strategy %v changed detection: findings=%d/%d redacted=%d/%d candidates=%d/%d",
				strategy, stats.Findings, ref.Findings, stats.RedactedBytes, ref.RedactedBytes, stats.Candidates, ref.Candidates)
		}
		if int64(len(out)) != stats.BytesRead {
			t.Fatalf("strategy %v: output length %d != input length %d", strategy, len(out), stats.BytesRead)
		}
	}
}

// TestMaskStrategyAcrossChunkBoundary places a secret across the engine's
// emission boundary (input larger than the chunk buffer, secret straddling
// it) and verifies length preservation holds exactly.
func TestMaskStrategyAcrossChunkBoundary(t *testing.T) {
	e := mustEngine(t, Config{MaskStrategy: MaskLengthPreserving, ChunkSize: 64 * 1024})

	pad := 64*1024 - 20 // secret straddles the first buffer boundary
	input := strings.Repeat(".", pad) + testGHToken + strings.Repeat(".", 4096)
	out, stats := redactAll(t, e, &chunkedReader{data: []byte(input), sizes: func(int) int { return 8 * 1024 }})

	if len(out) != len(input) {
		t.Fatalf("output length %d != input length %d", len(out), len(input))
	}
	if strings.Contains(out, testGHToken) {
		t.Fatal("secret survived masking across chunk boundary")
	}
	if got := out[pad : pad+len(testGHToken)]; got != strings.Repeat("*", len(testGHToken)) {
		t.Fatalf("masked region = %q", got)
	}
	if stats.RedactedBytes != int64(len(testGHToken)) {
		t.Fatalf("RedactedBytes = %d, want %d", stats.RedactedBytes, len(testGHToken))
	}
}

// TestMaskStrategyInvalidRejected verifies New rejects out-of-range
// strategies with ErrInvalidConfig.
func TestMaskStrategyInvalidRejected(t *testing.T) {
	for _, bad := range []MaskStrategy{-1, 3, 99} {
		if _, err := New(Config{MaskStrategy: bad}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New(MaskStrategy=%d) error = %v, want ErrInvalidConfig", int(bad), err)
		}
	}
}

// TestMaskStrategyStrings pins the names used by CLI flags and manifests.
func TestMaskStrategyStrings(t *testing.T) {
	cases := map[MaskStrategy]string{
		MaskFixedMarker:      "fixed-marker",
		MaskLengthPreserving: "length-preserving",
		MaskFormatPreserving: "format-preserving",
		MaskStrategy(42):     "unknown",
	}
	for strategy, want := range cases {
		if got := strategy.String(); got != want {
			t.Errorf("MaskStrategy(%d).String() = %q, want %q", int(strategy), got, want)
		}
	}
}
