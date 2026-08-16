// This file implements two JWT-based detectors sharing one parser: the
// standalone JWT detector (a bare JWS compact serialization,
// header.payload.signature, anywhere in the input with no surrounding
// context required) and the Supabase service-role key detector (the same
// shape, additionally requiring a `"role":"service_role"` claim in the
// decoded payload — the claim Supabase bakes into its highest-privilege
// API key, the one Postgres treats as bypassing row-level security).
// Contextual occurrences (Authorization headers, cookies) are also caught
// by the contextual rules; these rules exist for the bare tokens those
// rules cannot see — JWTs pasted into agent transcripts, log lines, and
// tool output.
//
// The shape enforced here follows the betterleaks standalone-JWT rule
// (both the header and the payload segment must begin with "ey" — the
// base64 encoding of "{" — which is what keeps the false-positive rate
// low on eyJ-heavy auth-debugging transcripts), tightened to the base64url
// alphabet RFC 7515 actually specifies for the two JSON segments.
package validators

import "encoding/base64"

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

// isJWTSignatureByte additionally admits '/' and '+' so signatures emitted
// by non-compliant standard-base64 encoders (which map '-'/'_' to
// '+'/'/') are still captured whole rather than truncated mid-signature.
func isJWTSignatureByte(c byte) bool {
	return isBase64URLByte(c) || c == '/' || c == '+'
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
// placeholders (isPlaceholder: repeated bytes, "xxxx...",
// keyboard runs) are rejected, so documentation examples with stub
// signatures never fire. The whole token, header through padding, is
// redacted.
//
// A signature run that ends exactly at the window edge is accepted: at
// EOF that is the true end of input, and mid-stream (a JWT longer than
// the rule's lookahead) redacting the buffered prefix protects strictly
// more than rejecting the whole token would.
//
// parseJWT also reports the window-relative bounds of the payload segment
// (excluding the "." separators on either side), so SupabaseServiceRoleKey
// can inspect its decoded claims without re-parsing the token shape.
func parseJWT(window []byte, trigStart, trigEnd int) (start, end, payStart, payEnd int, ok bool) {
	if trigStart > 0 {
		if p := window[trigStart-1]; isBase64URLByte(p) || p == '.' {
			return 0, 0, 0, 0, false
		}
	}

	// Header segment: the trigger plus the rest of its base64url run.
	pos := trigEnd
	for pos < len(window) && isBase64URLByte(window[pos]) {
		pos++
	}
	if pos-trigStart < jwtSegmentMinLen {
		return 0, 0, 0, 0, false
	}
	pos, ok = consumeByte(window, pos, '.')
	if !ok {
		return 0, 0, 0, 0, false
	}

	// Payload segment: must itself begin with "ey" (base64 of '{').
	segStart := pos
	if pos+2 > len(window) || window[pos] != 'e' || window[pos+1] != 'y' {
		return 0, 0, 0, 0, false
	}
	for pos < len(window) && isBase64URLByte(window[pos]) {
		pos++
	}
	if pos-segStart < jwtSegmentMinLen {
		return 0, 0, 0, 0, false
	}
	segEnd := pos
	pos, ok = consumeByte(window, pos, '.')
	if !ok {
		return 0, 0, 0, 0, false
	}

	// Signature segment, with up to two bytes of base64 padding.
	sigStart := pos
	for pos < len(window) && isJWTSignatureByte(window[pos]) {
		pos++
	}
	if pos-sigStart < jwtSignatureMinLen {
		return 0, 0, 0, 0, false
	}
	if isPlaceholder(window[sigStart:pos]) {
		return 0, 0, 0, 0, false
	}
	for pad := 0; pad < 2 && pos < len(window) && window[pos] == '='; pad++ {
		pos++
	}
	if pos < len(window) && (isAlnum(window[pos]) || window[pos] == '=') {
		return 0, 0, 0, 0, false
	}
	return trigStart, pos, segStart, segEnd, true
}

// JWT confirms a standalone JWS compact serialization. See parseJWT for
// the exact shape enforced.
func JWT(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	start, end, _, _, ok = parseJWT(window, trigStart, trigEnd)
	return start, end, ok
}

// supabaseServiceRoleClaimKey and supabaseServiceRoleClaimValue are the
// JSON member Supabase bakes into every service-role key's payload,
// distinguishing it from the low-privilege anon key ("role":"anon") and
// from arbitrary bearer JWTs. RFC 8259 JSON strings are always
// double-quoted, so the literal quote bytes are part of the match; only
// the whitespace some encoders insert around ':' is treated as optional.
const (
	supabaseServiceRoleClaimKey   = `"role"`
	supabaseServiceRoleClaimValue = `"service_role"`
)

// hasServiceRoleClaim reports whether decoded JSON (a JWT payload,
// already base64url-decoded) contains the member
// `"role":"service_role"`, tolerating optional spaces around the colon.
// It is a targeted scan rather than a full JSON parse: sufficient to
// disambiguate Supabase's own key shapes, and forgiving of a payload
// whose other fields are malformed or reordered.
func hasServiceRoleClaim(payload []byte) bool {
	// Every occurrence of `"role"` is examined, not just the first: a
	// payload can legitimately contain an earlier, unrelated occurrence
	// (e.g. a nested `"app_metadata":{"role":...}` member) before the
	// top-level claim.
	for base := 0; base < len(payload); {
		idx := indexLiteral(payload[base:], supabaseServiceRoleClaimKey)
		if idx < 0 {
			return false
		}
		pos := base + idx + len(supabaseServiceRoleClaimKey)
		base = pos
		pos = skipSpaces(payload, pos)
		if pos >= len(payload) || payload[pos] != ':' {
			continue
		}
		pos++
		pos = skipSpaces(payload, pos)
		if indexLiteral(payload[pos:], supabaseServiceRoleClaimValue) == 0 {
			return true
		}
	}
	return false
}

// SupabaseServiceRoleKey confirms the same JWS compact-serialization shape
// as JWT (see parseJWT), additionally base64url-decoding the payload
// segment and requiring a `"role":"service_role"` claim within it. A
// payload that fails to decode as base64url — truncated by the window, or
// simply not base64 — is rejected rather than guessed at.
func SupabaseServiceRoleKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	start, end, payStart, payEnd, ok := parseJWT(window, trigStart, trigEnd)
	if !ok {
		return 0, 0, false
	}
	seg := window[payStart:payEnd]
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(seg)))
	n, err := base64.RawURLEncoding.Decode(decoded, seg)
	if err != nil || !hasServiceRoleClaim(decoded[:n]) {
		return 0, 0, false
	}
	return start, end, true
}
