// Package span implements confirmed-span collection, deduplication,
// merging, precedence resolution, ordered release, and the redacting
// writer used by the streaming engine. See docs/DESIGN.md, section
// "internal/span", for the frozen contract this package implements.
//
// The package never retains input bytes: Span and Collector deal purely
// in absolute byte offsets.
package span

import "sort"

// Span is a confirmed redaction candidate expressed as an absolute,
// half-open byte range [Start, End) within the input stream.
//
// Rule is the index of the detection rule that produced the span, into
// whatever rule set the caller is using. Confidence is an opaque
// ordering value: higher means "more confident this is a true positive".
type Span struct {
	Start, End int64 // absolute input offsets, half-open, Start < End
	Rule       int   // index into the active rule set
	Confidence uint8
}

// entry is the Collector's internal representation of a merged span.
//
// start/end are the current union range of every span merged into this
// entry. rule/confidence are the attribution of the winning contributor
// (see "attribution" in the package doc for precedence rules).
// attribStart is the Start of the span that won attribution — it is
// tracked separately from start (the leftmost edge of the merged range)
// because the winning contributor need not be the leftmost one.
type entry struct {
	start, end  int64
	rule        int
	confidence  uint8
	attribStart int64
}

// Collector accumulates spans out of order, deduplicating and merging
// them eagerly, and releases them in Start order once the caller
// guarantees no further span can touch them.
//
// The zero value is a ready-to-use, empty Collector.
//
// Merge/precedence rules (deterministic — see docs/DESIGN.md):
//  1. Identical spans (same Start/End) dedupe: keep the highest
//     Confidence, then the lowest Rule index.
//  2. Overlapping or exactly adjacent (a.End == b.Start) spans merge into
//     their union. Attribution (Rule/Confidence of the merged result)
//     goes to the higher-Confidence contributor; ties break to the
//     contributor with the earlier original Start, then to the lower
//     Rule index.
//  3. Merging is transitive: a chain of overlapping/adjacent spans
//     collapses into a single span.
//
// entries is always kept sorted by start and, because merged spans are
// non-overlapping by construction, is therefore also sorted by end.
type Collector struct {
	entries []entry
}

// Add inserts s into the collector, merging it with any spans it
// overlaps or is adjacent to (transitively) and resolving attribution
// per the precedence rules documented on Collector.
//
// Add panics if s.Start >= s.End: this indicates a programmer error in
// the caller (e.g. a validator producing an empty or inverted range),
// not a data condition the collector can recover from.
func (c *Collector) Add(s Span) {
	if s.Start >= s.End {
		panic("span: Add: invalid span, Start must be < End")
	}

	old := c.entries
	oldLen := len(old)

	// old is sorted by start and (since entries are pairwise
	// non-overlapping) therefore also sorted by end. All entries that
	// overlap or are adjacent to s form a single contiguous index
	// range [lo, hi): see package tests for the proof sketch — briefly,
	// if old[i] neither overlaps nor touches s then either
	// old[i].end < s.Start (i is "before", so i < lo) or
	// old[i].Start > s.End (i is "after", so i >= hi); monotonicity of
	// start/end rules out any other index appearing between two
	// touching entries.
	lo := sort.Search(oldLen, func(i int) bool { return old[i].end >= s.Start })
	hi := sort.Search(oldLen, func(i int) bool { return old[i].start > s.End })

	newStart, newEnd := s.Start, s.End
	best := attrib{confidence: s.Confidence, start: s.Start, rule: s.Rule}

	for i := lo; i < hi; i++ {
		e := old[i]
		if e.start < newStart {
			newStart = e.start
		}
		if e.end > newEnd {
			newEnd = e.end
		}
		best = betterAttrib(best, attrib{confidence: e.confidence, start: e.attribStart, rule: e.rule})
	}

	merged := entry{
		start:       newStart,
		end:         newEnd,
		rule:        best.rule,
		confidence:  best.confidence,
		attribStart: best.start,
	}

	// Replace old[lo:hi] with the single merged entry. Note this can
	// grow the slice (when hi == lo, i.e. s touched nothing and is a
	// pure insertion) as well as shrink or keep it the same size (when
	// hi > lo, i.e. one or more entries were absorbed). copy is
	// specified to behave correctly even when source and destination
	// overlap (it behaves like memmove), which is what makes the
	// in-place shift below safe in every case — a naive two-append
	// splice is NOT safe here, because appending the new element at
	// index lo can clobber old[hi:] before it has been read whenever
	// hi == lo.
	tailLen := oldLen - hi
	newLen := lo + 1 + tailLen

	var entries []entry
	if newLen <= cap(old) {
		entries = old[:newLen]
	} else {
		newCap := 2 * cap(old)
		if newCap < newLen {
			newCap = newLen
		}
		entries = make([]entry, newLen, newCap)
		copy(entries, old[:oldLen])
	}
	copy(entries[lo+1:], entries[hi:oldLen])
	entries[lo] = merged

	c.entries = entries
}

// attrib is the (Confidence, original Start, Rule) tuple used to decide
// which contributor wins attribution when spans merge.
type attrib struct {
	confidence uint8
	start      int64
	rule       int
}

// betterAttrib returns whichever of a, b wins attribution: higher
// Confidence; tie broken by earlier Start; tie broken by lower Rule.
func betterAttrib(a, b attrib) attrib {
	if a.confidence != b.confidence {
		if a.confidence > b.confidence {
			return a
		}
		return b
	}
	if a.start != b.start {
		if a.start < b.start {
			return a
		}
		return b
	}
	if a.rule <= b.rule {
		return a
	}
	return b
}

// Release appends to dst every merged span whose End is <= limit, in
// Start order, and removes them from the collector. The returned spans
// are mutually non-overlapping (they always are, by construction).
//
// The engine's contract with Release is: once Release(limit) has been
// called, the engine will never subsequently Add a span with
// Start < limit. Under that contract, any merged span with End <= limit
// can never grow further (a span that could still merge with it would
// need a Start < limit, i.e. at or before its End), so it is safe to
// release. Spans with End > limit — including ones that overlap limit —
// stay held and are never split.
//
// Release is idempotent in the sense that calling it again with the same
// or a smaller limit returns no additional spans (dst is returned
// unchanged, aside from the append no-op).
func (c *Collector) Release(dst []Span, limit int64) []Span {
	n := len(c.entries)
	idx := sort.Search(n, func(i int) bool { return c.entries[i].end > limit })

	for i := 0; i < idx; i++ {
		e := c.entries[i]
		dst = append(dst, Span{Start: e.start, End: e.end, Rule: e.rule, Confidence: e.confidence})
	}

	// Compact the remaining (held) entries down to the front of the
	// backing array so it can be reused without unbounded growth.
	remaining := copy(c.entries, c.entries[idx:])
	c.entries = c.entries[:remaining]

	return dst
}

// Pending reports whether any span is still held by the collector (i.e.
// has not yet been released).
func (c *Collector) Pending() bool {
	return len(c.entries) > 0
}

// Reset clears all held state so the Collector can be reused, retaining
// its backing array's capacity.
func (c *Collector) Reset() {
	c.entries = c.entries[:0]
}
