package goredact

import (
	"bytes"
	"context"
	"math/rand"
	"testing"
)

// FuzzRedactChunkingEquivalence checks the engine's core invariants for
// arbitrary inputs and arbitrary read-chunking:
//
//  1. no panics on any byte sequence;
//  2. output is identical regardless of how the reader slices the input;
//  3. output equals the input with each confirmed (merged) span replaced
//     by exactly one marker — so confirmed span bytes never appear.
func FuzzRedactChunkingEquivalence(f *testing.F) {
	f.Add([]byte(nil), uint64(0))
	f.Add([]byte("plain text with no secrets at all"), uint64(1))
	f.Add([]byte(testGHToken), uint64(2))
	f.Add([]byte("a "+testGHToken+" b "+testSlackToken+" c"), uint64(3))
	f.Add([]byte(testGHToken+testSlackToken), uint64(4))
	f.Add([]byte("ghp_ghp_ghp_xoxb-xoxb-"), uint64(5))
	f.Add([]byte("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"), uint64(6)) // one byte short
	f.Add(bytes.Repeat([]byte("ghp_A1b2C3d4E5"), 700), uint64(7))       // > one 4096 chunk
	f.Add([]byte("\x00\xff\n ghp_\xf0 xoxb-"), uint64(8))

	f.Fuzz(func(t *testing.T, data []byte, seed uint64) {
		var findings []Finding
		e, err := New(Config{
			ChunkSize: 4096,
			OnFinding: func(fd Finding) { findings = append(findings, fd) },
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ctx := context.Background()

		var oneShot bytes.Buffer
		stats, err := e.Redact(ctx, &oneShot, bytes.NewReader(data))
		if err != nil {
			t.Fatalf("one-shot Redact: %v", err)
		}
		if stats.BytesRead != int64(len(data)) {
			t.Fatalf("BytesRead = %d, want %d", stats.BytesRead, len(data))
		}
		if stats.Findings != len(findings) {
			t.Fatalf("Stats.Findings = %d, OnFinding count = %d", stats.Findings, len(findings))
		}

		// Findings must be in input order, non-overlapping, in range; the
		// output must equal the splice reconstruction (which implies no
		// confirmed span's bytes survive at their position).
		var last int64 = -1
		for _, fd := range findings {
			if fd.Start < 0 || fd.End > int64(len(data)) || fd.Start >= fd.End || fd.Start < last {
				t.Fatalf("finding %+v invalid or out of order", fd)
			}
			last = fd.End
		}
		if want := spliceExpected(data, findings, DefaultMarker); oneShot.String() != want {
			t.Fatalf("one-shot output differs from splice reconstruction")
		}

		// Same input through seeded random chunking must be identical.
		rng := rand.New(rand.NewSource(int64(seed)))
		pieceCap := 1 + int(seed%89)
		var chunked bytes.Buffer
		_, err = e.Redact(ctx, &chunked,
			&chunkedReader{data: data, sizes: func(int) int { return 1 + rng.Intn(pieceCap) }})
		if err != nil {
			t.Fatalf("chunked Redact: %v", err)
		}
		if !bytes.Equal(oneShot.Bytes(), chunked.Bytes()) {
			t.Fatalf("chunked output differs from one-shot output")
		}
	})
}
