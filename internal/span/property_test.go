package span

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
)

// buildExpected simulates the desired end-to-end behaviour directly from
// a final (sorted, non-overlapping) set of merged spans: copy input
// bytes outside spans verbatim, and substitute exactly one copy of
// marker for each span's bytes. This is the ground truth that
// Collector+Writer, used together, must reproduce byte-for-byte.
func buildExpected(input []byte, merged []Span, marker []byte) []byte {
	var out bytes.Buffer
	cur := int64(0)
	for _, s := range merged {
		out.Write(input[cur:s.Start])
		out.Write(marker)
		cur = s.End
	}
	out.Write(input[cur:])
	return out.Bytes()
}

// TestCollectorWriterProperty is a property-based test: for many random
// binary inputs and random (possibly overlapping/adjacent/duplicate)
// spans, verify that running everything through Collector then Writer —
// split across randomly sized Emit calls, so spans routinely straddle
// call boundaries — reproduces buildExpected's byte-for-byte ground
// truth. Equality with buildExpected simultaneously establishes:
//
//	(a) no byte belonging to a merged span survives in the output — its
//	    entire range was replaced by the marker;
//	(b) output outside redacted spans equals input exactly;
//	(c) output ordering is preserved (segments appear in input order);
//	(d) each merged span produced exactly one marker.
func TestCollectorWriterProperty(t *testing.T) {
	const marker = "[REDACTED]"
	seed := int64(20260814)
	rng := rand.New(rand.NewSource(seed))

	const iterations = 500
	for iter := 0; iter < iterations; iter++ {
		n := rng.Intn(400) + 1 // input length in [1,400]
		input := make([]byte, n)
		rng.Read(input) // full byte range, including 0x00 and non-UTF8

		var c Collector
		numSpans := rng.Intn(30)
		for i := 0; i < numSpans; i++ {
			a := int64(rng.Intn(n + 1))
			b := int64(rng.Intn(n + 1))
			if a == b {
				continue // Add requires Start < End
			}
			if a > b {
				a, b = b, a
			}
			c.Add(Span{
				Start:      a,
				End:        b,
				Rule:       rng.Intn(8),
				Confidence: uint8(rng.Intn(256)),
			})
		}

		merged := c.Release(nil, int64(n))
		assertSortedNonOverlapping(t, merged)
		if c.Pending() {
			t.Fatalf("iter %d: Pending() = true after Release(n) covering entire input", iter)
		}

		expected := buildExpected(input, merged, []byte(marker))

		// Feed the input to Writer through randomly sized chunks, so
		// spans frequently straddle Emit call boundaries.
		var buf bytes.Buffer
		w := NewWriter(&buf, []byte(marker))

		off := int64(0)
		mi := 0 // index into merged spans not yet handed to Emit
		for off < int64(n) {
			remaining := int64(n) - off
			chunkLen := int64(rng.Intn(int(remaining))) + 1
			chunk := input[off : off+chunkLen]

			var chunkSpans []Span
			for mi < len(merged) && merged[mi].Start >= off && merged[mi].Start < off+chunkLen {
				chunkSpans = append(chunkSpans, merged[mi])
				mi++
			}

			if err := w.Emit(off, chunk, chunkSpans); err != nil {
				t.Fatalf("iter %d: Emit: %v", iter, err)
			}
			off += chunkLen
		}
		if mi != len(merged) {
			t.Fatalf("iter %d: %d merged spans never handed to Emit", iter, len(merged)-mi)
		}

		if !bytes.Equal(buf.Bytes(), expected) {
			t.Fatalf("iter %d: n=%d spans=%v\ngot  %q\nwant %q", iter, n, merged, buf.Bytes(), expected)
		}

		gotMarkers := bytes.Count(buf.Bytes(), []byte(marker))
		if gotMarkers != len(merged) {
			t.Fatalf("iter %d: marker appeared %d times, want %d (one per merged span)", iter, gotMarkers, len(merged))
		}

		wantRedacted := int64(0)
		for _, s := range merged {
			wantRedacted += s.End - s.Start
		}
		if got := w.RedactedBytes(); got != wantRedacted {
			t.Fatalf("iter %d: RedactedBytes() = %d, want %d", iter, got, wantRedacted)
		}
	}
}

// TestCollectorMatchesNaiveMergeProperty cross-checks the incremental,
// eagerly-merging Collector against a from-scratch sort+merge reference
// over many random span sets, out of Add order.
func TestCollectorMatchesNaiveMergeProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(99))

	const iterations = 300
	for iter := 0; iter < iterations; iter++ {
		numSpans := rng.Intn(50)
		spans := make([]Span, 0, numSpans)
		for i := 0; i < numSpans; i++ {
			a := int64(rng.Intn(120))
			b := int64(rng.Intn(120))
			if a == b {
				continue
			}
			if a > b {
				a, b = b, a
			}
			spans = append(spans, Span{
				Start:      a,
				End:        b,
				Rule:       rng.Intn(5),
				Confidence: uint8(rng.Intn(256)),
			})
		}

		// Add in a random (shuffled) order to ensure the incremental
		// algorithm is order-independent.
		order := rng.Perm(len(spans))
		var c Collector
		for _, idx := range order {
			c.Add(spans[idx])
		}
		got := c.Release(nil, 1<<62)
		assertSortedNonOverlapping(t, got)

		want := naiveMerge(spans)
		sort.Slice(want, func(i, j int) bool { return want[i].Start < want[j].Start })

		if !equalSpanSlices(got, want) {
			t.Fatalf("iter %d: mismatch\nspans: %v\ngot:   %v\nwant:  %v", iter, spans, got, want)
		}
	}
}

func equalSpanSlices(a, b []Span) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
