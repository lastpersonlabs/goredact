package span

import "io"

// Writer emits input bytes to an underlying io.Writer, replacing each
// redacted span's bytes with exactly one copy of a fixed marker.
//
// Writer tracks absolute input offsets across a sequence of Emit calls.
// The caller (the engine) must feed it consecutive, non-overlapping,
// gap-free input regions in ascending order — that is, the region passed
// to one Emit call must start exactly where the previous one ended (the
// very first call may start at any offset, e.g. 0). Each Emit call also
// carries the spans (already merged, sorted by Start, non-overlapping —
// as produced by Collector.Release) whose Start falls within that call's
// region.
//
// # Straddling spans
//
// A merged span may be longer than a single Emit call's region: it can
// start in one call and end in a later one. The contract for this case
// is:
//
//   - A span is reported to Emit exactly once, in the call whose region
//     contains the span's Start. Its End may be beyond that region.
//   - The caller must NOT pass that span (or any remainder of it) again
//     in later calls; Writer tracks the in-progress redaction internally
//     and automatically skips input bytes belonging to it across as many
//     subsequent Emit calls as needed, without emitting any further
//     marker for it.
//   - The marker is written exactly once, at the point the span starts.
//
// A span's Start must never be less than the offset of the region
// currently being processed (i.e. it must not start before or inside a
// still-pending straddling redaction, and it must not start before the
// current Emit call's off). Violating this, or feeding non-contiguous
// regions, is a programmer error and Writer panics.
type Writer struct {
	w      io.Writer
	marker []byte

	offset int64 // absolute offset expected at the next Emit call

	redacting  bool  // true while a straddling span is still being skipped
	pendingEnd int64 // absolute end offset of the in-progress straddling span

	bytesWritten  int64
	redactedBytes int64
}

// NewWriter returns a Writer that writes to w, replacing redacted span
// bytes with marker. marker is copied by reference and must not be
// mutated by the caller afterward.
func NewWriter(w io.Writer, marker []byte) *Writer {
	return &Writer{w: w, marker: marker}
}

// Emit writes data — which corresponds to the absolute input range
// [off, off+len(data)) — to the underlying writer, replacing the bytes
// covered by spans with the marker. See the Writer doc comment for the
// exact straddling-span contract.
//
// Emit always consumes the entirety of data; there is no partial
// consumption to report. It returns any error from the underlying
// io.Writer's Write, unmodified. Once Emit returns an error, the Writer
// must not be used again: its internal offset bookkeeping may not have
// advanced past the failed write.
func (w *Writer) Emit(off int64, data []byte, spans []Span) error {
	if off != w.offset {
		panic("span: Writer.Emit: non-contiguous input region")
	}
	end := off + int64(len(data))
	cur := off

	// Finish skipping a span that straddled in from a previous call.
	if w.redacting {
		skipTo := w.pendingEnd
		if skipTo > end {
			skipTo = end
		}
		w.redactedBytes += skipTo - cur
		cur = skipTo
		if cur >= w.pendingEnd {
			w.redacting = false
		}
	}

	for _, s := range spans {
		if s.Start < cur {
			panic("span: Writer.Emit: span starts before the current write position")
		}
		if s.End <= s.Start {
			panic("span: Writer.Emit: invalid span, Start must be < End")
		}
		if s.Start > end {
			panic("span: Writer.Emit: span Start outside the emitted region")
		}

		// Plain bytes before the span.
		if s.Start > cur {
			if err := w.writeAll(data[cur-off : s.Start-off]); err != nil {
				return err
			}
		}

		// Exactly one marker per span, written when it starts.
		if err := w.writeAll(w.marker); err != nil {
			return err
		}

		consumeTo := s.End
		if consumeTo > end {
			consumeTo = end
		}
		w.redactedBytes += consumeTo - s.Start
		cur = consumeTo

		if s.End > end {
			// Span straddles past this region; remember it and stop —
			// no further spans can legally start in this call's region
			// (they would have to start at or after s.End, which is
			// already past end).
			w.redacting = true
			w.pendingEnd = s.End
		}
	}

	// Trailing plain bytes after the last span (or all of data, if no
	// spans applied and nothing is pending).
	if cur < end {
		if err := w.writeAll(data[cur-off:]); err != nil {
			return err
		}
		cur = end
	}

	w.offset = end
	return nil
}

func (w *Writer) writeAll(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	n, err := w.w.Write(p)
	w.bytesWritten += int64(n)
	return err
}

// BytesWritten returns the total number of bytes written to the
// underlying io.Writer so far (plain input bytes plus one marker's
// worth of bytes per redacted span).
func (w *Writer) BytesWritten() int64 {
	return w.bytesWritten
}

// RedactedBytes returns the total number of original input bytes that
// have been replaced by markers so far (summed across all spans, and
// across all the Emit calls a straddling span was spread over).
func (w *Writer) RedactedBytes() int64 {
	return w.redactedBytes
}
