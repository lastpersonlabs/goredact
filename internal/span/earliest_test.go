package span

import "testing"

func TestEarliest(t *testing.T) {
	var c Collector

	if _, ok := c.Earliest(); ok {
		t.Fatal("Earliest() on an empty collector reported a span")
	}

	c.Add(Span{Start: 50, End: 60, Rule: 2, Confidence: 1})
	c.Add(Span{Start: 10, End: 20, Rule: 1, Confidence: 3})

	got, ok := c.Earliest()
	if !ok {
		t.Fatal("Earliest() = _, false with two held spans")
	}
	want := Span{Start: 10, End: 20, Rule: 1, Confidence: 3}
	if got != want {
		t.Fatalf("Earliest() = %+v, want %+v", got, want)
	}

	// Growing the earliest span through a merge must be reflected.
	c.Add(Span{Start: 5, End: 12, Rule: 4, Confidence: 3})
	got, ok = c.Earliest()
	if !ok || got.Start != 5 || got.End != 20 {
		t.Fatalf("Earliest() after merge = %+v, %v; want Start=5 End=20", got, ok)
	}

	// Releasing the earliest span moves Earliest to the next held one.
	var dst []Span
	dst = c.Release(dst, 30)
	if len(dst) != 1 {
		t.Fatalf("Release returned %d spans, want 1", len(dst))
	}
	got, ok = c.Earliest()
	if !ok || got.Start != 50 || got.End != 60 {
		t.Fatalf("Earliest() after release = %+v, %v; want Start=50 End=60", got, ok)
	}

	c.Reset()
	if _, ok := c.Earliest(); ok {
		t.Fatal("Earliest() after Reset reported a span")
	}
}
