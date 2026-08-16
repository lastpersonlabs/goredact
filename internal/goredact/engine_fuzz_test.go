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
//  2. output is identical regardless of how the reader slices the input,
//     for every combination of RecordAligned and MaskStrategy derived from
//     the fuzz seed — RecordAligned in particular is what makes the
//     released-span-carried-across-emission path in emitTo reachable at
//     all (see TestRecordAlignedCarriesReleasedSpanAcrossEmission), so
//     leaving it always false here would never exercise that path;
//  3. under MaskFixedMarker specifically, output equals the input with
//     each confirmed (merged) span replaced by exactly one marker — so
//     confirmed span bytes never appear. The other two strategies
//     transform per byte rather than per span, so they're checked instead
//     for the weaker (but still load-bearing) invariant that no
//     confirmed secret value appears verbatim in the output.
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
	f.Add([]byte("line one\nline two "+testGHToken+" trailing, no newline"), uint64(9))

	f.Fuzz(func(t *testing.T, data []byte, seed uint64) {
		recordAligned := seed%2 == 0
		maskStrategy := MaskStrategy((seed / 2) % 3)

		var findings []Finding
		e, err := New(Config{
			ChunkSize:     4096,
			EnableRules:   []string{"github-pat", "slack-bot-token"},
			MaskStrategy:  maskStrategy,
			RecordAligned: recordAligned,
			OnFinding:     func(fd Finding) { findings = append(findings, fd) },
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
		if stats.Findings != int64(len(findings)) {
			t.Fatalf("Stats.Findings = %d, OnFinding count = %d", stats.Findings, len(findings))
		}

		// Findings must be in input order, non-overlapping, and in range
		// regardless of mask strategy or record alignment.
		var last int64 = -1
		for _, fd := range findings {
			if fd.Start < 0 || fd.End > int64(len(data)) || fd.Start >= fd.End || fd.Start < last {
				t.Fatalf("finding %+v invalid or out of order", fd)
			}
			last = fd.End
		}
		if maskStrategy == MaskFixedMarker {
			// The splice reconstruction only holds for a fixed marker: the
			// other two strategies substitute per byte, not per span.
			if want := spliceExpected(data, findings, DefaultMarker); oneShot.String() != want {
				t.Fatalf("one-shot output differs from splice reconstruction")
			}
		} else {
			out := oneShot.Bytes()
			for _, fd := range findings {
				if bytes.Contains(out, data[fd.Start:fd.End]) {
					t.Fatalf("confirmed secret value leaked into output under mask strategy %v", maskStrategy)
				}
			}
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

// FuzzRedactAllRulesSecurity runs arbitrary bytes through the complete built-in
// catalog, including contextual and multi-line parsers. The smaller seed-rule
// target above is intentionally retained because it reaches more mutations per
// second; this target trades speed for breadth.
func FuzzRedactAllRulesSecurity(f *testing.F) {
	f.Add([]byte(nil), uint64(0))
	f.Add([]byte(`{"headers":"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc_DEF-1234567890\\n"}`), uint64(1))
	f.Add([]byte(`postgres://user:p%40ssword-with-entropy@example.invalid/db`), uint64(2))
	f.Add([]byte("postgres://user:unterminated%zz@/ bad://:@ -----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUFFS"), uint64(3))
	f.Add([]byte("\xff\xfe\x00Cookie: session=AbCdEfGhIjKlMnOpQrStUvWxYz012345; x=1\r\n"), uint64(4))
	f.Add(bytes.Repeat([]byte("A=\\\"%zz://:@\x00\xff\n"), 512), uint64(5))

	f.Fuzz(func(t *testing.T, data []byte, seed uint64) {
		const maxInput = 32 << 10
		if len(data) > maxInput {
			data = data[:maxInput]
		}

		run := func(src *chunkedReader) ([]byte, []Finding) {
			var findings []Finding
			e, err := New(Config{Profile: ProfileDeep, OnFinding: func(fd Finding) { findings = append(findings, fd) }})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			var out bytes.Buffer
			stats, err := e.Redact(context.Background(), &out, src)
			if err != nil {
				t.Fatalf("Redact: %v", err)
			}
			if stats.BytesRead != int64(len(data)) || stats.Findings != int64(len(findings)) {
				t.Fatalf("stats=%+v input=%d callbacks=%d", stats, len(data), len(findings))
			}
			if want := spliceExpected(data, findings, DefaultMarker); !bytes.Equal(out.Bytes(), []byte(want)) {
				t.Fatal("output differs from confirmed-span splice reconstruction")
			}
			return append([]byte(nil), out.Bytes()...), findings
		}

		one, _ := run(&chunkedReader{data: data, sizes: func(int) int { return len(data) + 1 }})
		rng := rand.New(rand.NewSource(int64(seed)))
		limit := 1 + int(seed%127)
		chunked, _ := run(&chunkedReader{data: data, sizes: func(int) int { return 1 + rng.Intn(limit) }})
		if !bytes.Equal(one, chunked) {
			t.Fatal("chunked and non-chunked outputs differ")
		}
	})
}
