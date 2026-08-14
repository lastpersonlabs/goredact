package span

import (
	"bytes"
	"strings"
	"testing"
)

func TestMaskingWriterLengthPreserving(t *testing.T) {
	var buf bytes.Buffer
	w := NewMaskingWriter(&buf, []byte("[REDACTED]"), MaskLengthPreserving)

	input := []byte("hello secret world")
	if err := w.Emit(0, input, []Span{{Start: 6, End: 12}}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	want := "hello ****** world"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
	if got := w.BytesWritten(); got != int64(len(input)) {
		t.Fatalf("BytesWritten() = %d, want %d (output length must equal input length)", got, len(input))
	}
	if got := w.RedactedBytes(); got != 6 {
		t.Fatalf("RedactedBytes() = %d, want 6", got)
	}
}

func TestMaskingWriterFormatPreserving(t *testing.T) {
	var buf bytes.Buffer
	w := NewMaskingWriter(&buf, nil, MaskFormatPreserving)

	input := []byte(`token="abZ9-_.:/+=@!\x00"end`)
	// Redact the quoted value: abZ9-_.:/+=@!\x00 → chars each map by class.
	start := int64(len(`token="`))
	end := int64(len(input) - len(`"end`))
	if err := w.Emit(0, input, []Span{{Start: start, End: end}}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	want := `token="xxX9-_.:/+=@**x99"end`
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
	if got := w.BytesWritten(); got != int64(len(input)) {
		t.Fatalf("BytesWritten() = %d, want %d", got, len(input))
	}
}

// TestMaskingWriterStraddling verifies that a span spread over several
// Emit calls accumulates a replacement of exactly the span's length, with
// no marker ever written.
func TestMaskingWriterStraddling(t *testing.T) {
	for _, strategy := range []MaskStrategy{MaskLengthPreserving, MaskFormatPreserving} {
		var buf bytes.Buffer
		w := NewMaskingWriter(&buf, []byte("[REDACTED]"), strategy)

		input := "aaSECRET1234secretbb"
		// Span covers input[2:18]; emit in three regions splitting it.
		span := Span{Start: 2, End: 18}
		if err := w.Emit(0, []byte(input[:6]), []Span{span}); err != nil {
			t.Fatalf("strategy %v Emit 1: %v", strategy, err)
		}
		if err := w.Emit(6, []byte(input[6:13]), nil); err != nil {
			t.Fatalf("strategy %v Emit 2: %v", strategy, err)
		}
		if err := w.Emit(13, []byte(input[13:]), nil); err != nil {
			t.Fatalf("strategy %v Emit 3: %v", strategy, err)
		}

		got := buf.String()
		if len(got) != len(input) {
			t.Fatalf("strategy %v output length = %d, want %d", strategy, len(got), len(input))
		}
		if strings.Contains(got, "REDACTED") {
			t.Fatalf("strategy %v wrote a marker: %q", strategy, got)
		}
		var want string
		if strategy == MaskLengthPreserving {
			want = "aa****************bb"
		} else {
			want = "aaXXXXXX9999xxxxxxbb"
		}
		if got != want {
			t.Fatalf("strategy %v got %q, want %q", strategy, got, want)
		}
		if w.RedactedBytes() != 16 {
			t.Fatalf("strategy %v RedactedBytes() = %d, want 16", strategy, w.RedactedBytes())
		}
	}
}

// TestMaskingWriterDiscardedInterior pins the degradation contract for
// zero-filled scratch standing in for discarded span-interior bytes: both
// preserving strategies mask 0x00 to '*', so length is still exact.
func TestMaskingWriterDiscardedInterior(t *testing.T) {
	for _, strategy := range []MaskStrategy{MaskLengthPreserving, MaskFormatPreserving} {
		var buf bytes.Buffer
		w := NewMaskingWriter(&buf, nil, strategy)

		// Span [1, 9); region 2 is zero scratch replaying discarded bytes.
		if err := w.Emit(0, []byte("pAB"), []Span{{Start: 1, End: 9}}); err != nil {
			t.Fatalf("strategy %v Emit 1: %v", strategy, err)
		}
		if err := w.Emit(3, make([]byte, 4), nil); err != nil {
			t.Fatalf("strategy %v Emit 2: %v", strategy, err)
		}
		if err := w.Emit(7, []byte("CDq"), nil); err != nil {
			t.Fatalf("strategy %v Emit 3: %v", strategy, err)
		}

		var want string
		if strategy == MaskLengthPreserving {
			want = "p********q"
		} else {
			want = "pXX****XXq"
		}
		if buf.String() != want {
			t.Fatalf("strategy %v got %q, want %q", strategy, buf.String(), want)
		}
	}
}

// TestMaskingWriterLongSpanBounded verifies masking stays within the fixed
// scratch block for spans far longer than it: one span longer than maskBuf
// masks correctly (the write path chunks internally).
func TestMaskingWriterLongSpanBounded(t *testing.T) {
	var buf bytes.Buffer
	w := NewMaskingWriter(&buf, nil, MaskLengthPreserving)

	input := bytes.Repeat([]byte("k"), 5000)
	if err := w.Emit(0, input, []Span{{Start: 0, End: 5000}}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got, want := buf.String(), strings.Repeat("*", 5000); got != want {
		t.Fatalf("long span masked incorrectly: len=%d first=%q", len(got), got[:1])
	}
}
