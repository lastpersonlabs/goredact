package span

import "io"

// MaskStrategy selects how a redacted span's bytes are replaced in the
// Writer's output.
type MaskStrategy uint8

const (
	// MaskFixedMarker writes exactly one copy of the fixed marker per
	// span, regardless of the span's length. This is the default.
	MaskFixedMarker MaskStrategy = iota

	// MaskLengthPreserving writes one '*' per redacted input byte, so
	// output length always equals input length.
	MaskLengthPreserving

	// MaskFormatPreserving writes one byte per redacted input byte,
	// preserving its coarse character class: uppercase letters become
	// 'X', lowercase letters 'x', digits '9'; the separator bytes
	// - _ . : / + = @ pass through verbatim; every other byte becomes
	// '*'. Output length equals input length and token shapes (JWT
	// dots, UUID dashes, base64 padding) survive. Note the preserved
	// separators and class shape ARE information about the original
	// secret; this strategy trades that disclosure for format fidelity
	// and must be an explicit caller choice.
	MaskFormatPreserving
)

// maskByte returns the replacement for one redacted input byte under a
// length- or format-preserving strategy (never called for
// MaskFixedMarker).
func maskByte(strategy MaskStrategy, c byte) byte {
	if strategy == MaskLengthPreserving {
		return '*'
	}
	switch {
	case c >= 'A' && c <= 'Z':
		return 'X'
	case c >= 'a' && c <= 'z':
		return 'x'
	case c >= '0' && c <= '9':
		return '9'
	case c == '-' || c == '_' || c == '.' || c == ':' ||
		c == '/' || c == '+' || c == '=' || c == '@':
		return c
	default:
		return '*'
	}
}

// Writer emits input bytes to an underlying io.Writer, replacing each
// redacted span's bytes according to a MaskStrategy: with exactly one copy
// of a fixed marker (MaskFixedMarker), or byte for byte with masked
// replacements (MaskLengthPreserving, MaskFormatPreserving).
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
//     and automatically consumes input bytes belonging to it across as
//     many subsequent Emit calls as needed, without emitting any further
//     marker for it.
//   - Under MaskFixedMarker the marker is written exactly once, at the
//     point the span starts, and the span's remaining bytes are skipped.
//     Under the preserving strategies each Emit call instead writes the
//     masked replacement of the span bytes its region covers, so the
//     replacement accumulates to exactly the span's length across calls.
//
// # Discarded span interiors
//
// The engine may discard the interior bytes of a very long merged span
// under buffer pressure and replay them as zero-filled scratch. Under
// MaskFixedMarker those bytes are never read. Under the preserving
// strategies the zero bytes mask to '*' (0x00 is in no preserved class),
// so length preservation still holds exactly and format preservation
// degrades to '*' fill for the discarded stretch only.
//
// A span's Start must never be less than the offset of the region
// currently being processed (i.e. it must not start before or inside a
// still-pending straddling redaction, and it must not start before the
// current Emit call's off). Violating this, or feeding non-contiguous
// regions, is a programmer error and Writer panics.
type Writer struct {
	w        io.Writer
	marker   []byte
	strategy MaskStrategy

	// maskBuf is the fixed scratch block masked replacements are staged
	// in under the preserving strategies. Lazily allocated once, so
	// masking stays allocation-bounded regardless of span or input size.
	maskBuf []byte

	offset int64 // absolute offset expected at the next Emit call

	redacting  bool  // true while a straddling span is still being consumed
	pendingEnd int64 // absolute end offset of the in-progress straddling span

	bytesWritten  int64
	redactedBytes int64
}

// NewWriter returns a Writer that writes to w, replacing redacted span
// bytes with exactly one marker per span (MaskFixedMarker). marker is
// copied by reference and must not be mutated by the caller afterward.
func NewWriter(w io.Writer, marker []byte) *Writer {
	return NewMaskingWriter(w, marker, MaskFixedMarker)
}

// NewMaskingWriter returns a Writer that writes to w, replacing redacted
// span bytes according to strategy. marker is used only by
// MaskFixedMarker; it is copied by reference and must not be mutated by
// the caller afterward.
func NewMaskingWriter(w io.Writer, marker []byte, strategy MaskStrategy) *Writer {
	return &Writer{w: w, marker: marker, strategy: strategy}
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

	// Finish consuming a span that straddled in from a previous call.
	if w.redacting {
		skipTo := w.pendingEnd
		if skipTo > end {
			skipTo = end
		}
		if err := w.writeMasked(data[cur-off : skipTo-off]); err != nil {
			return err
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
		// The contract places a span in the Emit call whose region
		// [off, end) contains its Start, so Start == end is already a
		// violation: admitting it would write a marker here and, while a
		// straddling span is pending, let the bogus span overwrite
		// pendingEnd and expose the old span's tail unmasked.
		if s.Start >= end {
			panic("span: Writer.Emit: span Start outside the emitted region")
		}

		// Plain bytes before the span.
		if s.Start > cur {
			if err := w.writeAll(data[cur-off : s.Start-off]); err != nil {
				return err
			}
		}

		// Exactly one marker per span, written when it starts — or, under
		// a preserving strategy, the masked replacement of the span bytes
		// this region covers.
		if w.strategy == MaskFixedMarker {
			if err := w.writeAll(w.marker); err != nil {
				return err
			}
		}

		consumeTo := s.End
		if consumeTo > end {
			consumeTo = end
		}
		if err := w.writeMasked(data[s.Start-off : consumeTo-off]); err != nil {
			return err
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

// writeMasked writes the masked replacement of the redacted input bytes
// src. It is a no-op under MaskFixedMarker (those bytes are simply
// skipped; the span's single marker is written separately). Replacements
// are staged through the fixed maskBuf block, so arbitrarily long spans
// mask without allocation proportional to their length.
func (w *Writer) writeMasked(src []byte) error {
	if w.strategy == MaskFixedMarker || len(src) == 0 {
		return nil
	}
	if w.maskBuf == nil {
		w.maskBuf = make([]byte, 512)
	}
	for len(src) > 0 {
		n := len(src)
		if n > len(w.maskBuf) {
			n = len(w.maskBuf)
		}
		for i, c := range src[:n] {
			w.maskBuf[i] = maskByte(w.strategy, c)
		}
		if err := w.writeAll(w.maskBuf[:n]); err != nil {
			return err
		}
		src = src[n:]
	}
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
// underlying io.Writer so far: plain input bytes plus, per redacted span,
// one marker's worth of bytes (MaskFixedMarker) or one masked byte per
// span byte (the preserving strategies, under which BytesWritten tracks
// input length exactly).
func (w *Writer) BytesWritten() int64 {
	return w.bytesWritten
}

// RedactedBytes returns the total number of original input bytes that
// have been replaced by markers so far (summed across all spans, and
// across all the Emit calls a straddling span was spread over).
func (w *Writer) RedactedBytes() int64 {
	return w.redactedBytes
}
