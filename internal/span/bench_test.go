package span

import "testing"

// BenchmarkAddRelease simulates the engine's steady-state usage pattern:
// spans arrive in roughly increasing Start order (as a streaming scan
// would produce), occasionally overlapping/adjacent to their neighbours,
// and are periodically released as the read frontier advances. Both
// Collector and the dst slice are reused across the whole benchmark, so
// steady-state allocations should be amortised to (close to) zero.
func BenchmarkAddRelease(b *testing.B) {
	var c Collector
	dst := make([]Span, 0, 64)

	b.ReportAllocs()
	b.ResetTimer()

	var start int64
	for i := 0; i < b.N; i++ {
		// Step by 5, span length 8: neighbouring spans overlap by 3
		// bytes, which exercises the merge path on most Adds while
		// still advancing steadily (like real detections in a scan).
		start += 5
		c.Add(Span{
			Start:      start,
			End:        start + 8,
			Rule:       i % 16,
			Confidence: uint8(i),
		})

		if i%32 == 0 {
			limit := start - 64 // keep a trailing window held
			dst = c.Release(dst[:0], limit)
		}
	}
	dst = c.Release(dst[:0], start+8)
	_ = dst
}
