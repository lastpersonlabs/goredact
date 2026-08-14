// This file implements the standalone JWT detector: a bare JWS compact
// serialization (header.payload.signature) anywhere in the input, with no
// surrounding context required. Contextual occurrences (Authorization
// headers, cookies) are also caught by the contextual rules; this rule
// exists for the bare tokens those rules cannot see — JWTs pasted into
// agent transcripts, log lines, and tool output.
//
// The shape enforced here follows the betterleaks standalone-JWT rule
// (both the header and the payload segment must begin with "ey" — the
// base64 encoding of "{" — which is what keeps the false-positive rate
// low on eyJ-heavy auth-debugging transcripts), tightened to the base64url
// alphabet RFC 7515 actually specifies for the two JSON segments.
package validators

import "github.com/lastpersonlabs/goredact/internal/entropy"

const (
	// jwtSegmentMinLen is the minimum length of the header and payload
	// segments, including their required "ey" prefix. Real JWT headers
	// are never shorter (base64url of {"alg":"none"} is already 19
	// bytes), and requiring the same of the payload rejects short
	// dot-separated base64 blobs that merely look JWT-ish.
	jwtSegmentMinLen = 19

	// jwtSignatureMinLen is the minimum signature segment length. The
	// shortest real signatures (HS256) are 43 base64url bytes; 10 keeps
	// headroom for truncated-but-real material while rejecting trailing
	// version-suffix noise ("v1.2.3"-shaped strings).
	jwtSignatureMinLen = 10
)

// isBase64URLByte is the RFC 4648 base64url alphabet, the alphabet of the
// JWS header and payload segments.
func isBase64URLByte(c byte) bool {
	return isAlnum(c) || c == '-' || c == '_'
}

// isJWTSignatureByte additionally admits '/' so signatures emitted by
// non-compliant standard-base64 encoders are still captured whole rather
// than truncated mid-signature.
func isJWTSignatureByte(c byte) bool {
	return isBase64URLByte(c) || c == '/'
}

// JWT confirms a standalone JWS compact serialization: trigger "eyJ"
// starting the header segment, then
//
//	<base64url, >= jwtSegmentMinLen> "." "ey" <base64url, >= jwtSegmentMinLen>
//	"." <signature, >= jwtSignatureMinLen> "="{0,2}
//
// The byte before the trigger must not be a base64url byte or '.' (the
// trigger must start the token, not continue a longer blob — this is
// also what rejects the trigger's second firing at the payload segment of
// a JWT already matched whole from its header; a preceding '=' stays
// legal because assignments, "ID_TOKEN=eyJ...", are exactly where bare
// JWTs appear). The byte after the token must not be alphanumeric or
// further padding. Signatures that are
// placeholders (entropy.IsPlaceholder: repeated bytes, "xxxx...",
// keyboard runs) are rejected, so documentation examples with stub
// signatures never fire. The whole token, header through padding, is
// redacted.
//
// A signature run that ends exactly at the window edge is accepted: at
// EOF that is the true end of input, and mid-stream (a JWT longer than
// the rule's lookahead) redacting the buffered prefix protects strictly
// more than rejecting the whole token would.
func JWT(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if trigStart > 0 {
		if p := window[trigStart-1]; isBase64URLByte(p) || p == '.' {
			return 0, 0, false
		}
	}

	// Header segment: the trigger plus the rest of its base64url run.
	pos := trigEnd
	for pos < len(window) && isBase64URLByte(window[pos]) {
		pos++
	}
	if pos-trigStart < jwtSegmentMinLen {
		return 0, 0, false
	}
	pos, ok = consumeByte(window, pos, '.')
	if !ok {
		return 0, 0, false
	}

	// Payload segment: must itself begin with "ey" (base64 of '{').
	segStart := pos
	if pos+2 > len(window) || window[pos] != 'e' || window[pos+1] != 'y' {
		return 0, 0, false
	}
	for pos < len(window) && isBase64URLByte(window[pos]) {
		pos++
	}
	if pos-segStart < jwtSegmentMinLen {
		return 0, 0, false
	}
	pos, ok = consumeByte(window, pos, '.')
	if !ok {
		return 0, 0, false
	}

	// Signature segment, with up to two bytes of base64 padding.
	sigStart := pos
	for pos < len(window) && isJWTSignatureByte(window[pos]) {
		pos++
	}
	if pos-sigStart < jwtSignatureMinLen {
		return 0, 0, false
	}
	if entropy.IsPlaceholder(window[sigStart:pos]) {
		return 0, 0, false
	}
	for pad := 0; pad < 2 && pos < len(window) && window[pos] == '='; pad++ {
		pos++
	}
	if pos < len(window) && (isAlnum(window[pos]) || window[pos] == '=') {
		return 0, 0, false
	}
	return trigStart, pos, true
}
