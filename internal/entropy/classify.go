package entropy

// Class buckets a candidate byte slice by its byte-level shape, used to
// apply structural (shape-based) rejections that entropy alone cannot: a
// syntactically perfect UUID or hex hash has exactly the same entropy as a
// random secret of the same length, so it has to be recognized by shape.
type Class int

const (
	// ClassUnknown is anything that does not match one of the more
	// specific classes below.
	ClassUnknown Class = iota
	// ClassUUID is a canonical 8-4-4-4-12 hyphenated hex UUID, any case.
	ClassUUID
	// ClassHexHash is a pure hex string (any case) at one of the common
	// hash digest lengths: 32 (MD5), 40 (SHA-1, git SHA), 64 (SHA-256),
	// 96 (SHA-384), 128 (SHA-512).
	ClassHexHash
	// ClassDigits is a non-empty run of ASCII decimal digits only.
	ClassDigits
	// ClassBase64ish is dominated by the base64/base64url alphabet
	// (A-Z, a-z, 0-9, +, /, -, _, =) without matching a more specific
	// class above.
	ClassBase64ish
	// ClassWordlike is mostly-lowercase-letters (allowing '_'/'-'
	// separators) with entropy low enough, relative to that alphabet, to
	// read as an English-ish word or identifier rather than a random
	// token.
	ClassWordlike
)

// wordlikeEntropyCeiling is the Shannon entropy (bits/byte) below which a
// letters-and-separators-only candidate is considered word-like rather
// than random. The lowercase+"_"+"-" alphabet has a theoretical per-byte
// maximum of log2(28) ~= 4.81 bits/byte; genuine English-ish compounds
// ("hello_world_this_is_config") land in the high 3s, while random draws
// from the same 28-symbol alphabet at typical candidate lengths land
// close to the theoretical maximum. 4.2 was chosen empirically against
// this package's test fixtures to sit between the two.
const wordlikeEntropyCeiling = 4.2

// wordlikeMinLowerFrac is the minimum fraction of a candidate's bytes that
// must be lowercase ASCII letters for it to be considered for
// ClassWordlike (the remainder may only be '_' or '-'; any other byte
// disqualifies the candidate immediately, see isWordlike).
const wordlikeMinLowerFrac = 0.8

// hexHashLens is the set of byte lengths recognized as common hash digest
// lengths when a candidate is pure hex.
var hexHashLens = map[int]bool{32: true, 40: true, 64: true, 96: true, 128: true}

// Classify buckets b into one of the Class values above. It is
// deterministic, byte-oriented, and bounded by len(b): it never allocates
// more than a fixed amount of stack state and never iterates b more than a
// small constant number of times. Classify(nil) and Classify of an empty
// slice are both ClassUnknown.
func Classify(b []byte) Class {
	if len(b) == 0 {
		return ClassUnknown
	}
	if isUUID(b) {
		return ClassUUID
	}
	if isHexHash(b) {
		return ClassHexHash
	}
	if isAllDigits(b) {
		return ClassDigits
	}
	if isWordlike(b) {
		return ClassWordlike
	}
	if isBase64ish(b) {
		return ClassBase64ish
	}
	return ClassUnknown
}

// isHexDigit reports whether c is an ASCII hex digit, any case.
func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// isUUID reports whether b is a canonical 36-byte hyphenated UUID
// (8-4-4-4-12 hex groups), any case.
func isUUID(b []byte) bool {
	if len(b) != 36 {
		return false
	}
	for i, c := range b {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexDigit(c) {
				return false
			}
		}
	}
	return true
}

// isHexHash reports whether b is pure hex (any case) at one of the common
// hash digest lengths.
func isHexHash(b []byte) bool {
	if !hexHashLens[len(b)] {
		return false
	}
	for _, c := range b {
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

// isAllDigits reports whether every byte of b is an ASCII decimal digit. A
// non-empty precondition is enforced by Classify (len(b) == 0 short-circuits
// to ClassUnknown before this is called); this function itself treats an
// empty slice as false, matching "there is nothing to confirm".
func isAllDigits(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isWordlike reports whether b is mostly lowercase ASCII letters (allowing
// '_'/'-' separators, disallowing everything else including digits and
// uppercase) with entropy low enough, relative to that alphabet, to read
// as a word-like token rather than a random one. Any byte outside
// [a-z_-] disqualifies b immediately: mixed-case or digit-containing
// candidates are judged as base64-ish/unknown instead, since those
// alphabets are the ones real secrets actually use.
func isWordlike(b []byte) bool {
	lower := 0
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			lower++
		case c == '_' || c == '-':
			// separator; does not count toward the lowercase fraction
			// but does not disqualify either.
		default:
			return false
		}
	}
	if lower == 0 {
		return false
	}
	if float64(lower)/float64(len(b)) < wordlikeMinLowerFrac {
		return false
	}
	return Shannon(b) < wordlikeEntropyCeiling
}

// isBase64ish reports whether every byte of b is in the base64/base64url
// alphabet (A-Z, a-z, 0-9, +, /, -, _, =). It does not require valid
// base64 padding or length; it is a coarse alphabet-membership check used
// as the fallback bucket for random-looking tokens that are not one of the
// more specific classes.
func isBase64ish(b []byte) bool {
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '=' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}
