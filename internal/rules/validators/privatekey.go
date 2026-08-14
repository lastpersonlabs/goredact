package validators

// Private-key material validators (ENG-99): PEM-encapsulated private keys
// (raw multi-line and JSON-escaped single-line forms) and PuTTY PPK
// private-key sections. Both are window-based validators: the engine hands
// them a bounded window (trigger + up to the rule's MaxLookahead), which
// may be truncated at a chunk or input boundary, and they must never panic
// or index out of range on any byte sequence.
//
// Span semantics, PEMPrivateKey:
//
//   - Full match: trigger start through the closing "-----" of the END
//     marker, extended past an immediately following ESCAPED newline (the
//     two-byte sequences `\r` and/or `\n`, covering JSON-escaped keys). A
//     real newline byte after the END marker is NOT consumed.
//   - Truncation fail-safe: when no acceptable END marker is found in the
//     window (window exhausted, or the scan stopped at a byte that cannot
//     be part of a PEM body), the validator still confirms — over-redaction
//     is safe, leaking is not — with span trigger start through the last
//     base64 byte seen, provided at least one plausible body run (>= 16
//     consecutive base64 bytes) followed the header. A header followed only
//     by prose ("-----BEGIN PRIVATE KEY----- is the PEM header") has no
//     plausible run and is rejected.
//
// Span semantics, PuTTYPrivateKey: only the Private-Lines section is
// redacted — from the first byte of "Private-Lines:" through the last
// base64 byte of the last private body line seen in the window (the
// terminating newline is not included; the public portion of the file is
// left intact). The same truncation fail-safe applies once the
// Private-Lines header and at least one plausible body line are in-window.

import "bytes"

const (
	// pemLabelMax bounds a BEGIN/END label scan; RFC 7468 labels are far
	// shorter, so anything longer is not a PEM marker.
	pemLabelMax = 64

	// pemPlausibleRun is the minimum length of a run of consecutive base64
	// bytes that counts as evidence of real encoded key material. Real PEM
	// and PPK body lines are 64+ bytes; prose words are far shorter.
	pemPlausibleRun = 16

	// pemMaxShortRuns bounds how many consecutive short (< pemPlausibleRun)
	// base64 runs the body scan tolerates before giving up. Encapsulated
	// PEM headers (Proc-Type:, DEK-Info:) produce at most ~10; running
	// prose produces one per word, so this both rejects prose and keeps
	// per-trigger work small on trigger floods.
	pemMaxShortRuns = 24
)

var (
	pemDashes       = []byte("-----")
	pemEndPrefix    = []byte("-----END ")
	pemPrivateLabel = []byte("PRIVATE KEY")
	pemEscCR        = []byte(`\r`)
	pemEscLF        = []byte(`\n`)
	ppkPrivateLines = []byte("\nPrivate-Lines:")
)

// pemIsBase64 reports whether c can appear in a base64 body (standard
// alphabet plus padding).
func pemIsBase64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || isDigit(c) || c == '+' || c == '/' || c == '='
}

// pemIsLabelByte reports whether c can appear in a PEM BEGIN/END label
// (uppercase letters, digits, and spaces — covers "RSA PRIVATE KEY",
// "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK", ...).
func pemIsLabelByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || isDigit(c) || c == ' '
}

// pemHasAt reports whether lit occurs in window at offset pos. It never
// indexes out of range.
func pemHasAt(window []byte, pos int, lit []byte) bool {
	return pos >= 0 && pos <= len(window)-len(lit) && bytes.Equal(window[pos:pos+len(lit)], lit)
}

// pemLabelEnd scans a PEM label starting at start and returns the offset of
// the '-' that terminates it. It fails when the label runs past the window,
// exceeds pemLabelMax, or contains a non-label byte.
func pemLabelEnd(window []byte, start int) (end int, ok bool) {
	pos := start
	for {
		if pos >= len(window) || pos-start > pemLabelMax {
			return 0, false
		}
		c := window[pos]
		if c == '-' {
			return pos, true
		}
		if !pemIsLabelByte(c) {
			return 0, false
		}
		pos++
	}
}

// pemEndMarker parses a "-----END <label>-----" marker whose first '-' is
// at pos and whose label contains "PRIVATE KEY". On success it returns the
// offset one past the closing dashes, extended past an immediately
// following escaped `\r` and/or `\n` two-byte sequence (JSON-escaped keys);
// a real newline byte is never consumed.
func pemEndMarker(window []byte, pos int) (end int, ok bool) {
	if !pemHasAt(window, pos, pemEndPrefix) {
		return 0, false
	}
	labelStart := pos + len(pemEndPrefix)
	labelEnd, ok := pemLabelEnd(window, labelStart)
	if !ok {
		return 0, false
	}
	if !bytes.Contains(window[labelStart:labelEnd], pemPrivateLabel) {
		return 0, false
	}
	if !pemHasAt(window, labelEnd, pemDashes) {
		return 0, false
	}
	end = labelEnd + len(pemDashes)
	if pemHasAt(window, end, pemEscCR) {
		end += 2
	}
	if pemHasAt(window, end, pemEscLF) {
		end += 2
	}
	return end, true
}

// PEMPrivateKey confirms a PEM-encapsulated private-key block. The trigger
// is "-----BEGIN " (trailing space included). The header label must contain
// "PRIVATE KEY" (so CERTIFICATE and PUBLIC KEY blocks are rejected), then
// the body is scanned byte-wise — base64 characters, whitespace, the
// encapsulated-header punctuation ':' and ',', '-' (checked for an END
// marker first), and the two-byte escapes `\n` `\r` `\t` `\"` so
// JSON-escaped single-line keys in structured logs are covered — until the
// matching "-----END ...PRIVATE KEY...-----" marker or the window ends.
// See the file comment for the exact span and truncation semantics.
func PEMPrivateKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if trigStart < 0 || trigEnd < trigStart || trigEnd > len(window) {
		return 0, 0, false
	}

	// Header: "<label>-----" with a label containing "PRIVATE KEY".
	labelEnd, ok := pemLabelEnd(window, trigEnd)
	if !ok {
		return 0, 0, false
	}
	if !bytes.Contains(window[trigEnd:labelEnd], pemPrivateLabel) {
		return 0, 0, false
	}
	if !pemHasAt(window, labelEnd, pemDashes) {
		return 0, 0, false
	}

	// Body scan. A "run" is a maximal sequence of base64 bytes; runs of
	// pemPlausibleRun or more are evidence of real key material.
	i := labelEnd + len(pemDashes)
	runStart := -1
	lastB64End := -1
	hasPlausible := false
	shortRuns := 0

	closeRun := func(at int) bool {
		if runStart < 0 {
			return true
		}
		n := at - runStart
		runStart = -1
		if n >= pemPlausibleRun {
			hasPlausible = true
			shortRuns = 0
			return true
		}
		shortRuns++
		return shortRuns <= pemMaxShortRuns
	}

scan:
	for i < len(window) {
		c := window[i]
		if pemIsBase64(c) {
			if runStart < 0 {
				runStart = i
			}
			i++
			lastB64End = i
			continue
		}
		if !closeRun(i) {
			break scan // too many prose-like short runs: give up early
		}
		switch c {
		case ' ', '\t', '\r', '\n', ':', ',':
			// Whitespace and encapsulated-header punctuation
			// (Proc-Type: 4,ENCRYPTED / DEK-Info: ...).
			i++
		case '\\':
			// JSON-style two-byte escapes inside string-embedded keys.
			if i+1 < len(window) {
				switch window[i+1] {
				case 'n', 'r', 't', '"':
					i += 2
					continue scan
				}
			}
			break scan
		case '-':
			if e, found := pemEndMarker(window, i); found {
				if !hasPlausible {
					// Marker text with no body between BEGIN and END is
					// prose/template text, not a key.
					return 0, 0, false
				}
				return trigStart, e, true
			}
			// Not an END marker for a private key (e.g. the hyphen in
			// "DEK-Info" or "AES-128-CBC", or a mismatched END label):
			// treat as body punctuation and keep looking.
			i++
		default:
			break scan // byte that cannot be part of a PEM body
		}
	}
	closeRun(i) // close a run cut off by the end of the window

	// Truncation fail-safe: no END marker in the window, but plausible
	// body material followed the header — confirm through the last base64
	// byte seen rather than risk leaking a truncated key.
	if hasPlausible {
		return trigStart, lastB64End, true
	}
	return 0, 0, false
}

// PuTTYPrivateKey confirms the private section of a PuTTY PPK file. The
// trigger is "PuTTY-User-Key-File-"; the version digit must be 2 or 3
// (followed by ':'). The validator then locates the "Private-Lines: N"
// header at a line start and consumes up to N base64 body lines. Span:
// first byte of "Private-Lines:" through the last base64 byte of the last
// body line seen (public portion stays). If "Private-Lines:" never appears
// in the window the validator reports no match; once it has appeared, the
// same truncation fail-safe as PEMPrivateKey applies (confirm on partial
// bodies, requiring at least one line with a plausible >= 16-byte base64
// run).
func PuTTYPrivateKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if trigStart < 0 || trigEnd < trigStart || trigEnd > len(window) {
		return 0, 0, false
	}

	// Version: a single digit 2 or 3, immediately followed by ':'.
	if trigEnd+2 > len(window) {
		return 0, 0, false
	}
	if v := window[trigEnd]; v != '2' && v != '3' {
		return 0, 0, false
	}
	if window[trigEnd+1] != ':' {
		return 0, 0, false
	}

	// "Private-Lines:" at a line start (preceded by '\n').
	rel := bytes.Index(window[trigEnd:], ppkPrivateLines)
	if rel < 0 {
		return 0, 0, false
	}
	secStart := trigEnd + rel + 1 // first byte of "Private-Lines:"
	p := secStart + len(ppkPrivateLines) - 1

	// Line count: optional spaces, 1-5 digits, optional spaces, optional
	// '\r', then '\n'. Anything else (prose such as "Private-Lines: 14 is
	// a field", or a window truncated inside the header line, which cannot
	// have leaked any key bytes yet) is not a private-lines section.
	for p < len(window) && (window[p] == ' ' || window[p] == '\t') {
		p++
	}
	digStart := p
	for p < len(window) && isDigit(window[p]) {
		p++
	}
	nd := p - digStart
	if nd == 0 || nd > 5 {
		return 0, 0, false
	}
	n := 0
	for _, c := range window[digStart:p] {
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return 0, 0, false
	}
	for p < len(window) && (window[p] == ' ' || window[p] == '\t') {
		p++
	}
	if p < len(window) && window[p] == '\r' {
		p++
	}
	if p >= len(window) || window[p] != '\n' {
		return 0, 0, false
	}
	p++

	// Up to n base64 body lines. The walk stops early at a non-base64
	// line, junk after a line's base64 prefix, or the end of the window
	// (truncation); whatever was seen up to that point is the span.
	count := 0
	lastEnd := -1
	hasPlausible := false
	for count < n && p < len(window) {
		lineStart := p
		for p < len(window) && pemIsBase64(window[p]) {
			p++
		}
		if p == lineStart {
			break
		}
		lastEnd = p
		if p-lineStart >= pemPlausibleRun {
			hasPlausible = true
		}
		count++
		if p < len(window) && window[p] == '\r' {
			p++
		}
		if p >= len(window) || window[p] != '\n' {
			break
		}
		p++
	}
	if lastEnd < 0 || !hasPlausible {
		return 0, 0, false
	}
	return secStart, lastEnd, true
}
