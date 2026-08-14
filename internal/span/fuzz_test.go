package span

import (
	"encoding/binary"
	"sort"
	"testing"
)

// naiveMerge is an independent, batch-oriented reference implementation:
// sort every valid (Start < End) span, then do a classic single-pass
// interval merge, tracking attribution with the same precedence formula
// documented on Collector (higher Confidence wins; tie -> earlier
// original Start; tie -> lower Rule). It shares the attrib/betterAttrib
// primitives with the production Add path (those simply encode the
// DESIGN.md precedence rule and are covered directly by
// TestAddMergePrecedence), but merges in a structurally different way
// (upfront sort + linear scan, vs. Collector's incremental
// binary-search-and-splice), making it a useful cross-check for the
// incremental algorithm's bookkeeping.
func naiveMerge(spans []Span) []Span {
	valid := make([]Span, 0, len(spans))
	for _, s := range spans {
		if s.Start < s.End {
			valid = append(valid, s)
		}
	}
	sort.Slice(valid, func(i, j int) bool {
		if valid[i].Start != valid[j].Start {
			return valid[i].Start < valid[j].Start
		}
		return valid[i].End < valid[j].End
	})

	var merged []entry
	for _, s := range valid {
		cand := attrib{confidence: s.Confidence, start: s.Start, rule: s.Rule}
		if len(merged) > 0 && s.Start <= merged[len(merged)-1].end {
			last := &merged[len(merged)-1]
			if s.End > last.end {
				last.end = s.End
			}
			best := betterAttrib(attrib{confidence: last.confidence, start: last.attribStart, rule: last.rule}, cand)
			last.confidence, last.attribStart, last.rule = best.confidence, best.start, best.rule
			continue
		}
		merged = append(merged, entry{start: s.Start, end: s.End, rule: s.Rule, confidence: s.Confidence, attribStart: s.Start})
	}

	out := make([]Span, len(merged))
	for i, e := range merged {
		out[i] = Span{Start: e.start, End: e.end, Rule: e.rule, Confidence: e.confidence}
	}
	return out
}

// releaseLimits derives a handful of interesting Release limits from the
// reference's merged spans: each span's Start, End-1 (still holds it)
// and End (releases it), so fuzzing exercises partial-release boundary
// behaviour, not just "release everything at once".
func releaseLimits(want []Span) []int64 {
	set := map[int64]bool{}
	for _, s := range want {
		set[s.Start] = true
		set[s.End-1] = true
		set[s.End] = true
	}
	limits := make([]int64, 0, len(set))
	for v := range set {
		limits = append(limits, v)
	}
	sort.Slice(limits, func(i, j int) bool { return limits[i] < limits[j] })
	return limits
}

const fuzzRecSize = 6

func encodeSpanRecords(recs [][4]uint16) []byte {
	out := make([]byte, 0, len(recs)*fuzzRecSize)
	for _, r := range recs {
		var b [fuzzRecSize]byte
		binary.LittleEndian.PutUint16(b[0:2], r[0])
		binary.LittleEndian.PutUint16(b[2:4], r[1])
		b[4] = byte(r[2])
		b[5] = byte(r[3])
		out = append(out, b[:]...)
	}
	return out
}

// FuzzCollector fuzzes raw span tuples (decoded from the fuzz corpus'
// bytes in fixed-width records) and checks the Collector's released
// output against naiveMerge, plus structural invariants (sorted,
// non-overlapping, respects the Release limit) at every intermediate
// Release call.
func FuzzCollector(f *testing.F) {
	f.Add([]byte{})
	f.Add(encodeSpanRecords([][4]uint16{{0, 5, 0, 0}, {5, 10, 1, 255}}))               // adjacent merge
	f.Add(encodeSpanRecords([][4]uint16{{0, 10, 0, 5}, {2, 4, 1, 200}}))               // nested, attribution flip
	f.Add(encodeSpanRecords([][4]uint16{{0, 5, 0, 5}, {0, 5, 1, 5}, {0, 5, 2, 5}}))    // identical dedupe
	f.Add(encodeSpanRecords([][4]uint16{{10, 20, 0, 1}, {0, 5, 1, 1}, {5, 10, 2, 1}})) // chain, reverse order
	f.Add(encodeSpanRecords([][4]uint16{{0, 1, 0, 0}, {65535, 1, 0, 0}}))              // degenerate/edge values

	f.Fuzz(func(t *testing.T, data []byte) {
		var spans []Span
		for i := 0; i+fuzzRecSize <= len(data); i += fuzzRecSize {
			start := int64(binary.LittleEndian.Uint16(data[i:i+2])) % 1000
			end := int64(binary.LittleEndian.Uint16(data[i+2:i+4])) % 1000
			if start == end {
				continue
			}
			if start > end {
				start, end = end, start
			}
			spans = append(spans, Span{
				Start:      start,
				End:        end,
				Rule:       int(data[i+4]),
				Confidence: data[i+5],
			})
		}
		if len(spans) == 0 {
			return
		}

		var c Collector
		for _, s := range spans {
			c.Add(s)
		}

		want := naiveMerge(spans)
		sort.Slice(want, func(i, j int) bool { return want[i].Start < want[j].Start })

		var released []Span
		for _, limit := range releaseLimits(want) {
			got := c.Release(nil, limit)
			assertSortedNonOverlapping(t, got)
			for _, s := range got {
				if s.End > limit {
					t.Fatalf("Release(%d) returned span %v with End > limit", limit, s)
				}
			}
			released = append(released, got...)
		}
		released = append(released, c.Release(nil, 1<<62)...)

		if c.Pending() {
			t.Fatalf("Pending() = true after draining every span with Release")
		}
		assertSortedNonOverlapping(t, released)
		if !equalSpanSlices(released, want) {
			t.Fatalf("spans=%v\ngot  %v\nwant %v", spans, released, want)
		}
	})
}
