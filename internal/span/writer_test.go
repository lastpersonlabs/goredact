package span

import (
	"bytes"
	"testing"
)

func TestWriterBasicEmit(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, []byte("[REDACTED]"))

	input := []byte("hello secret world")
	// "secret" is input[6:12]
	spans := []Span{{Start: 6, End: 12}}

	if err := w.Emit(0, input, spans); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	want := "hello [REDACTED] world"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
	if got := w.RedactedBytes(); got != 6 {
		t.Fatalf("RedactedBytes() = %d, want 6", got)
	}
	if got := w.BytesWritten(); got != int64(len(want)) {
		t.Fatalf("BytesWritten() = %d, want %d", got, len(want))
	}
}

func TestWriterMultipleSpansOneCall(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, []byte("*"))

	input := []byte("aaXXbbYYcc")
	spans := []Span{{Start: 2, End: 4}, {Start: 6, End: 8}}

	if err := w.Emit(0, input, spans); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	want := "aa*bb*cc"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
	if got := w.RedactedBytes(); got != 4 {
		t.Fatalf("RedactedBytes() = %d, want 4", got)
	}
}

func TestWriterNoSpans(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, []byte("[X]"))
	input := []byte("plain data, nothing redacted")
	if err := w.Emit(0, input, nil); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if buf.String() != string(input) {
		t.Fatalf("got %q, want %q", buf.String(), input)
	}
	if w.RedactedBytes() != 0 {
		t.Fatalf("RedactedBytes() = %d, want 0", w.RedactedBytes())
	}
}

func TestWriterEntireRegionRedacted(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, []byte("M"))
	input := []byte("xxxx")
	if err := w.Emit(0, input, []Span{{Start: 0, End: 4}}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if buf.String() != "M" {
		t.Fatalf("got %q, want %q", buf.String(), "M")
	}
	if w.RedactedBytes() != 4 {
		t.Fatalf("RedactedBytes() = %d, want 4", w.RedactedBytes())
	}
}

// TestWriterStraddling exercises the straddling contract: a single span
// that starts in one Emit call and ends in a later one, at every
// possible split point of a small input, plus 3-way splits.
func TestWriterStraddling(t *testing.T) {
	input := []byte("0123456789")
	spanStart, spanEnd := int64(3), int64(8) // redacts "34567"

	for split := 1; split < len(input); split++ {
		t.Run("", func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf, []byte("#"))

			first := input[:split]
			second := input[split:]

			var spans1, spans2 []Span
			if spanStart < int64(split) {
				spans1 = []Span{{Start: spanStart, End: spanEnd}}
			} else {
				spans2 = []Span{{Start: spanStart, End: spanEnd}}
			}

			if err := w.Emit(0, first, spans1); err != nil {
				t.Fatalf("Emit 1: %v", err)
			}
			if err := w.Emit(int64(split), second, spans2); err != nil {
				t.Fatalf("Emit 2: %v", err)
			}

			want := "012#89"
			if buf.String() != want {
				t.Fatalf("split=%d: got %q, want %q", split, buf.String(), want)
			}
			if got := w.RedactedBytes(); got != spanEnd-spanStart {
				t.Fatalf("split=%d: RedactedBytes() = %d, want %d", split, got, spanEnd-spanStart)
			}
		})
	}
}

// TestWriterStraddlingMultipleRegions splits a span across three Emit
// calls (one byte at a time in the middle).
func TestWriterStraddlingMultipleRegions(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, []byte("#"))

	input := []byte("0123456789")
	// span [2,9) starts in first chunk, straddles through several
	// single-byte chunks, ends in the last chunk.
	spans := []Span{{Start: 2, End: 9}}

	if err := w.Emit(0, input[0:3], spans); err != nil { // "012", span starts at 2
		t.Fatalf("emit0: %v", err)
	}
	for i := 3; i < 9; i++ {
		if err := w.Emit(int64(i), input[i:i+1], nil); err != nil {
			t.Fatalf("emit at %d: %v", i, err)
		}
	}
	if err := w.Emit(9, input[9:10], nil); err != nil {
		t.Fatalf("final emit: %v", err)
	}

	want := "01#9"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
	if got := w.RedactedBytes(); got != 7 {
		t.Fatalf("RedactedBytes() = %d, want 7", got)
	}
}

func TestWriterMarkerExactlyOncePerSpan(t *testing.T) {
	var buf bytes.Buffer
	marker := []byte("<M>")
	w := NewWriter(&buf, marker)

	input := make([]byte, 20)
	for i := range input {
		input[i] = 'a'
	}
	spans := []Span{{Start: 5, End: 15}}

	// split the emit so the span straddles across 4 calls
	if err := w.Emit(0, input[0:6], spans); err != nil {
		t.Fatal(err)
	}
	if err := w.Emit(6, input[6:10], nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Emit(10, input[10:14], nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Emit(14, input[14:20], nil); err != nil {
		t.Fatal(err)
	}

	count := bytes.Count(buf.Bytes(), marker)
	if count != 1 {
		t.Fatalf("marker appeared %d times, want 1; output=%q", count, buf.String())
	}
}

func TestWriterPanicsOnNonContiguousRegion(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on non-contiguous region")
		}
	}()
	var buf bytes.Buffer
	w := NewWriter(&buf, []byte("#"))
	_ = w.Emit(0, []byte("abc"), nil)
	_ = w.Emit(5, []byte("def"), nil) // gap: should have been 3
}

func TestWriterPanicsOnSpanBeforeCursor(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on span starting before current position")
		}
	}()
	var buf bytes.Buffer
	w := NewWriter(&buf, []byte("#"))
	_ = w.Emit(0, []byte("abcdef"), []Span{{Start: 3, End: 5}, {Start: 1, End: 2}})
}

type errWriter struct{ err error }

func (e errWriter) Write(p []byte) (int, error) { return 0, e.err }

func TestWriterPropagatesUnderlyingError(t *testing.T) {
	wantErr := bytes.ErrTooLarge
	w := NewWriter(errWriter{wantErr}, []byte("#"))
	err := w.Emit(0, []byte("abc"), nil)
	if err != wantErr {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}
