package span

import (
	"reflect"
	"testing"
)

// release is a small test helper: Release everything currently held,
// regardless of End, by using math.MaxInt64 as the limit.
func releaseAll(t *testing.T, c *Collector) []Span {
	t.Helper()
	return c.Release(nil, 1<<62)
}

func TestAddMergePrecedence(t *testing.T) {
	tests := []struct {
		name string
		in   []Span
		want []Span
	}{
		{
			name: "single span",
			in:   []Span{{Start: 0, End: 5, Rule: 1, Confidence: 1}},
			want: []Span{{Start: 0, End: 5, Rule: 1, Confidence: 1}},
		},
		{
			name: "identical spans dedupe keeping highest confidence",
			in: []Span{
				{Start: 0, End: 5, Rule: 3, Confidence: 1},
				{Start: 0, End: 5, Rule: 2, Confidence: 9},
				{Start: 0, End: 5, Rule: 1, Confidence: 5},
			},
			want: []Span{{Start: 0, End: 5, Rule: 2, Confidence: 9}},
		},
		{
			name: "identical spans tie-break on lowest rule",
			in: []Span{
				{Start: 0, End: 5, Rule: 4, Confidence: 7},
				{Start: 0, End: 5, Rule: 1, Confidence: 7},
				{Start: 0, End: 5, Rule: 2, Confidence: 7},
			},
			want: []Span{{Start: 0, End: 5, Rule: 1, Confidence: 7}},
		},
		{
			name: "nested span absorbed, outer attribution wins on confidence",
			in: []Span{
				{Start: 0, End: 10, Rule: 1, Confidence: 9},
				{Start: 2, End: 4, Rule: 2, Confidence: 1},
			},
			want: []Span{{Start: 0, End: 10, Rule: 1, Confidence: 9}},
		},
		{
			name: "nested span wins attribution via higher confidence",
			in: []Span{
				{Start: 0, End: 10, Rule: 1, Confidence: 1},
				{Start: 2, End: 4, Rule: 2, Confidence: 9},
			},
			want: []Span{{Start: 0, End: 10, Rule: 2, Confidence: 9}},
		},
		{
			name: "overlapping spans merge into union",
			in: []Span{
				{Start: 0, End: 6, Rule: 1, Confidence: 5},
				{Start: 4, End: 10, Rule: 2, Confidence: 5},
			},
			want: []Span{{Start: 0, End: 10, Rule: 1, Confidence: 5}}, // tie -> earlier start
		},
		{
			name: "adjacent spans merge (End == Start)",
			in: []Span{
				{Start: 0, End: 5, Rule: 1, Confidence: 5},
				{Start: 5, End: 10, Rule: 2, Confidence: 5},
			},
			want: []Span{{Start: 0, End: 10, Rule: 1, Confidence: 5}},
		},
		{
			name: "non-adjacent disjoint spans stay separate",
			in: []Span{
				{Start: 0, End: 5, Rule: 1, Confidence: 5},
				{Start: 6, End: 10, Rule: 2, Confidence: 5},
			},
			want: []Span{
				{Start: 0, End: 5, Rule: 1, Confidence: 5},
				{Start: 6, End: 10, Rule: 2, Confidence: 5},
			},
		},
		{
			name: "chain of overlaps merges transitively",
			in: []Span{
				{Start: 0, End: 3, Rule: 1, Confidence: 1},
				{Start: 2, End: 5, Rule: 2, Confidence: 2},
				{Start: 4, End: 7, Rule: 3, Confidence: 3},
				{Start: 6, End: 9, Rule: 4, Confidence: 9},
			},
			want: []Span{{Start: 0, End: 9, Rule: 4, Confidence: 9}},
		},
		{
			name: "bridging span merges two previously disjoint spans",
			in: []Span{
				{Start: 0, End: 2, Rule: 1, Confidence: 5},
				{Start: 8, End: 10, Rule: 2, Confidence: 5},
				{Start: 2, End: 8, Rule: 3, Confidence: 1}, // touches both, adjacent to first
			},
			want: []Span{{Start: 0, End: 10, Rule: 1, Confidence: 5}}, // tie -> earliest original start
		},
		{
			name: "reverse order input produces same merged result",
			in: []Span{
				{Start: 6, End: 9, Rule: 4, Confidence: 9},
				{Start: 4, End: 7, Rule: 3, Confidence: 3},
				{Start: 2, End: 5, Rule: 2, Confidence: 2},
				{Start: 0, End: 3, Rule: 1, Confidence: 1},
			},
			want: []Span{{Start: 0, End: 9, Rule: 4, Confidence: 9}},
		},
		{
			name: "confidence tie broken by earlier start, not merged start",
			in: []Span{
				{Start: 5, End: 10, Rule: 9, Confidence: 5},
				{Start: 0, End: 6, Rule: 1, Confidence: 5},
			},
			want: []Span{{Start: 0, End: 10, Rule: 1, Confidence: 5}},
		},
		{
			name: "attribution start tie broken by lowest rule",
			in: []Span{
				{Start: 0, End: 6, Rule: 9, Confidence: 5},
				{Start: 0, End: 10, Rule: 1, Confidence: 5},
			},
			want: []Span{{Start: 0, End: 10, Rule: 1, Confidence: 5}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c Collector
			for _, s := range tt.in {
				c.Add(s)
			}
			got := releaseAll(t, &c)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Add sequence %v\ngot  %v\nwant %v", tt.in, got, tt.want)
			}
			if c.Pending() {
				t.Errorf("Pending() = true after releasing everything")
			}
		})
	}
}

func TestAddPanicsOnInvalidSpan(t *testing.T) {
	cases := []Span{
		{Start: 5, End: 5},
		{Start: 5, End: 4},
		{Start: -1, End: -1},
	}
	for _, s := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Add(%+v) did not panic", s)
				}
			}()
			var c Collector
			c.Add(s)
		}()
	}
}

func assertSortedNonOverlapping(t *testing.T, spans []Span) {
	t.Helper()
	for i := 1; i < len(spans); i++ {
		if spans[i-1].Start > spans[i].Start {
			t.Fatalf("not sorted by Start: %v", spans)
		}
		if spans[i-1].End > spans[i].Start {
			t.Fatalf("overlapping released spans: %v", spans)
		}
	}
}

func TestReleaseBoundary(t *testing.T) {
	var c Collector
	c.Add(Span{Start: 0, End: 5, Rule: 1, Confidence: 1})
	c.Add(Span{Start: 5, End: 10, Rule: 2, Confidence: 1}) // adjacent -> merges to [0,10)
	c.Add(Span{Start: 20, End: 25, Rule: 3, Confidence: 1})
	c.Add(Span{Start: 30, End: 100, Rule: 4, Confidence: 1}) // straddles the limit

	// Nothing releasable below the first merged span's End.
	got := c.Release(nil, 9)
	if len(got) != 0 {
		t.Fatalf("Release(9) = %v, want empty (merged span [0,10) not yet fully behind limit)", got)
	}
	if !c.Pending() {
		t.Fatalf("Pending() = false, want true")
	}

	// Release exactly at the merged span's End.
	got = c.Release(nil, 10)
	want := []Span{{Start: 0, End: 10, Rule: 1, Confidence: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Release(10) = %v, want %v", got, want)
	}

	// Release up to a limit that includes [20,25) but a span straddling
	// the limit ([30,100)) must stay held.
	got = c.Release(nil, 50)
	want = []Span{{Start: 20, End: 25, Rule: 3, Confidence: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Release(50) = %v, want %v", got, want)
	}
	if !c.Pending() {
		t.Fatalf("Pending() = false, want true (span [30,100) should still be held)")
	}

	// Idempotent: repeated Release at same limit yields nothing new.
	got = c.Release(nil, 50)
	if len(got) != 0 {
		t.Fatalf("repeated Release(50) = %v, want empty", got)
	}

	// Finally release the straddling span once the limit passes its End.
	got = c.Release(nil, 100)
	want = []Span{{Start: 30, End: 100, Rule: 4, Confidence: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Release(100) = %v, want %v", got, want)
	}
	if c.Pending() {
		t.Fatalf("Pending() = true, want false")
	}
}

func TestReleaseAppendsToDst(t *testing.T) {
	var c Collector
	c.Add(Span{Start: 0, End: 5, Rule: 1, Confidence: 1})

	dst := []Span{{Start: -100, End: -90, Rule: 99, Confidence: 0}}
	got := c.Release(dst, 100)
	if len(got) != 2 {
		t.Fatalf("expected append, got %v", got)
	}
	if got[0] != dst[0] {
		t.Fatalf("Release must not disturb pre-existing dst contents")
	}
}

func TestInterleavedAddRelease(t *testing.T) {
	var c Collector

	c.Add(Span{Start: 0, End: 5, Rule: 1, Confidence: 1})
	got := c.Release(nil, 5)
	assertSortedNonOverlapping(t, got)
	if len(got) != 1 {
		t.Fatalf("expected 1 released span, got %v", got)
	}

	// Add more after releasing; should not resurrect released spans or
	// merge with them.
	c.Add(Span{Start: 3, End: 8, Rule: 2, Confidence: 1})
	got = c.Release(nil, 8)
	assertSortedNonOverlapping(t, got)
	want := []Span{{Start: 3, End: 8, Rule: 2, Confidence: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	c.Add(Span{Start: 100, End: 110, Rule: 3, Confidence: 1})
	c.Add(Span{Start: 105, End: 108, Rule: 4, Confidence: 1}) // nested, no-op on range
	c.Add(Span{Start: 200, End: 210, Rule: 5, Confidence: 1})

	got = c.Release(nil, 110)
	assertSortedNonOverlapping(t, got)
	want = []Span{{Start: 100, End: 110, Rule: 3, Confidence: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if !c.Pending() {
		t.Fatalf("Pending() = false, want true ([200,210) still held)")
	}

	got = releaseAll(t, &c)
	want = []Span{{Start: 200, End: 210, Rule: 5, Confidence: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestResetReuse(t *testing.T) {
	var c Collector
	c.Add(Span{Start: 0, End: 5, Rule: 1, Confidence: 1})
	c.Add(Span{Start: 10, End: 20, Rule: 2, Confidence: 1})
	if !c.Pending() {
		t.Fatalf("Pending() = false before Reset, want true")
	}

	c.Reset()
	if c.Pending() {
		t.Fatalf("Pending() = true after Reset, want false")
	}
	got := releaseAll(t, &c)
	if len(got) != 0 {
		t.Fatalf("Release after Reset = %v, want empty", got)
	}

	// Behaves exactly like a fresh Collector afterward.
	c.Add(Span{Start: 0, End: 5, Rule: 7, Confidence: 3})
	got = releaseAll(t, &c)
	want := []Span{{Start: 0, End: 5, Rule: 7, Confidence: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("post-Reset Add/Release = %v, want %v", got, want)
	}
}

func TestManySpansStayNonOverlappingAndSorted(t *testing.T) {
	var c Collector
	// A mix of overlapping clusters and disjoint spans, added out of
	// order, must always release sorted & non-overlapping.
	spans := []Span{
		{Start: 50, End: 60, Rule: 1, Confidence: 1},
		{Start: 0, End: 10, Rule: 2, Confidence: 1},
		{Start: 55, End: 65, Rule: 3, Confidence: 1},
		{Start: 5, End: 8, Rule: 4, Confidence: 1},
		{Start: 100, End: 110, Rule: 5, Confidence: 1},
		{Start: 9, End: 12, Rule: 6, Confidence: 1},
		{Start: 62, End: 70, Rule: 7, Confidence: 1},
	}
	for _, s := range spans {
		c.Add(s)
	}
	got := releaseAll(t, &c)
	assertSortedNonOverlapping(t, got)

	// Expect three merged groups: [0,12), [50,70), [100,110)
	want := []Span{
		{Start: 0, End: 12},
		{Start: 50, End: 70},
		{Start: 100, End: 110},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d spans, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Start != want[i].Start || got[i].End != want[i].End {
			t.Errorf("span %d: got [%d,%d), want [%d,%d)", i, got[i].Start, got[i].End, want[i].Start, want[i].End)
		}
	}
}
