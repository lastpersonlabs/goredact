// Package entropy implements deterministic, allocation-conscious heuristics
// for judging whether a short byte slice "looks like" a secret: order-0
// Shannon entropy, alphabet-aware classification (UUID, hex hash, digit
// run, base64-ish, word-like), and detection of common non-secret
// placeholder values.
//
// # Bounded candidates only
//
// Every function in this package operates on a single, already-bounded
// candidate slice — typically the value a rule's Validate function just
// captured from its (already bounded) window. Nothing here scans,
// tokenizes, or slides a window over arbitrary input, and none of it is
// safe or meaningful to call on a whole document: entropy measured over
// megabytes of mixed text is not a useful signal, and the classification
// heuristics assume they are looking at one token, not a stream. Callers
// MUST hand this package short, pre-extracted candidates (see Options.
// MinLen/MaxLen for the bounds the generic contextual rules use) and must
// never invoke Shannon, BitsTotal, Classify, IsPlaceholder, or Secretlike
// directly on unbounded input.
//
// All functions are pure, byte-oriented, and safe to call on arbitrary
// (including non-UTF-8, non-printable) bytes without panicking — including
// nil or empty slices.
//
// # Hashes, UUIDs, IDs, and source examples
//
// Deterministic-looking data — UUIDs, hex hashes (git SHAs, sha256sums,
// etc.), and pure digit runs (database IDs, timestamps) — is bucketed by
// Classify and, by default, rejected by Secretlike via the Options.
// RejectUUID / RejectHexHash / RejectDigits knobs used by the generic
// contextual rules in internal/rules/validators/generic.go. This is a
// deliberate false-positive reduction for those CONTEXTUAL/heuristic rules
// only: git commit SHAs, database primary keys, request IDs, and worked
// examples in documentation are extremely common near assignment-style
// trigger words ("token = <sha>", "id = <uuid>") and are not secrets.
// Word-like values (English-ish lowercase tokens, e.g. config option
// names) are rejected unconditionally by Secretlike, since a value that
// classifies as ClassWordlike is — by construction of that class — a
// low-entropy token, never a plausible secret.
//
// Deterministic PROVIDER rules (e.g. github-pat, slack-bot-token in
// internal/rules/specs/seed.json) do not use this package at all: their
// validators confirm an exact, well-known token shape and are entirely
// unaffected by these heuristics.
package entropy

import "math"

// Shannon returns the order-0 Shannon entropy of b, in bits per byte:
// -sum(p(c) * log2(p(c))) over the observed byte value distribution. It
// ranges from 0 (every byte identical) to 8 (all 256 byte values observed
// with equal frequency, unreachable for any b shorter than 256 bytes).
// Shannon(nil) and Shannon of an empty slice are both 0 by convention: an
// empty candidate carries no information.
//
// This is an empirical, order-0 (single-byte-frequency) measure: it does
// not detect structure such as repeated substrings, alternating patterns,
// or bigram statistics. It is intended to run over short (bytes to low
// hundreds of bytes) candidate slices, never over whole documents.
func Shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// BitsTotal returns Shannon(b) * len(b): the total (not per-byte) entropy
// of b. It is a convenience for callers that want to reason about absolute
// information content rather than a per-byte rate — e.g. comparing two
// candidates of different lengths on the same footing.
func BitsTotal(b []byte) float64 {
	return Shannon(b) * float64(len(b))
}

// Options configures Secretlike. Every field is opt-in: its zero value
// disables that check (MinLen/MaxLen/MinBitsPerByte/MaxRepeatRun of 0 mean
// "no bound"; the Reject* booleans default to false, i.e. "do not reject
// this class"). Callers construct Options explicitly per rule rather than
// relying on a single default, since the right thresholds are a function
// of what a rule's trigger implies about the surrounding text (see
// PresetAssignmentValue and PresetLooseToken for the two presets used by
// the generic contextual rules).
type Options struct {
	// MinLen and MaxLen bound the candidate's byte length. A candidate
	// shorter than MinLen or longer than MaxLen (when the respective
	// bound is > 0) is never secretlike, regardless of its content.
	MinLen, MaxLen int

	// MinBitsPerByte is the minimum Shannon(b) (bits per byte) a
	// candidate must reach, once it has cleared length, placeholder, and
	// classification checks. Because a candidate's alphabet limits its
	// achievable entropy (lowercase hex maxes out at 4 bits/byte,
	// unpadded base64 at 6), this threshold is chosen per rule relative
	// to the alphabets that rule's trigger context tends to produce, not
	// as one universal cutoff — see the preset doc comments below for
	// the reasoning behind 3.4 and 3.7.
	MinBitsPerByte float64

	// RejectUUID, RejectHexHash, and RejectDigits reject candidates that
	// Classify buckets as ClassUUID, ClassHexHash, or ClassDigits
	// respectively, regardless of their entropy. These are structural
	// rejections: a syntactically perfect UUID or hex hash is exactly as
	// "random-looking" as a real secret of the same length, so entropy
	// alone cannot distinguish them — the shape has to.
	RejectUUID, RejectHexHash, RejectDigits bool

	// MaxRepeatRun rejects candidates containing a run of MaxRepeatRun+1
	// or more identical consecutive bytes (0 disables this check). This
	// catches placeholder patterns like "aaaaaaaaaaaa" or
	// "XXXXXXXXXXXX" that IsPlaceholder's keyword list does not.
	MaxRepeatRun int
}

// PresetAssignmentValue is the Options used for tight "key = value" style
// assignments (generic-api-key-assignment, generic-password-assignment):
// values in this position are typically API keys, tokens, or passwords
// with a fairly narrow, deliberately-random alphabet (base62/base64-ish),
// so:
//   - MinLen/MaxLen of 12-128 excludes short config flags and excludes
//     implausibly long values (embedded certs, multi-line blobs) that a
//     single-line assignment value should not contain.
//   - MinBitsPerByte of 3.4 sits comfortably above the ~2.7-3.0 bits/byte
//     typical of English words and common placeholder phrases, but below
//     the ~4.5-6 bits/byte typical of real random base62/base64 secrets
//     of this length — chosen empirically against this package's test
//     fixtures rather than derived from a closed-form bound, since a
//     handful of "in-between" alphabets (structured lowercase-hex-like
//     identifiers) are already excluded structurally by RejectHexHash.
//   - RejectUUID/RejectHexHash/RejectDigits are all true: assignment
//     values matching those shapes are overwhelmingly IDs, hashes, or
//     example data, not secrets, in this context.
//   - MaxRepeatRun of 4 catches "aaaa..."/"xxxx..." placeholders that
//     slip past the keyword list in IsPlaceholder.
var PresetAssignmentValue = Options{
	MinLen:         12,
	MaxLen:         128,
	MinBitsPerByte: 3.4,
	RejectUUID:     true,
	RejectHexHash:  true,
	RejectDigits:   true,
	MaxRepeatRun:   4,
}

// PresetLooseToken is the Options used for the weaker "token" trigger
// (generic-bearer-like-token-assignment), which fires on far more
// non-secret code (`token = csv.next()`, `token: <cursor>`) than a
// dedicated api_key/password trigger does, so it demands more from the
// value before calling it secretlike:
//   - MinLen/MaxLen of 16-256: bearer-like tokens run longer than typical
//     password fields, and the rule additionally requires length >= 20 at
//     the validator level (stricter than this preset alone).
//   - MinBitsPerByte of 3.7 is higher than PresetAssignmentValue's 3.4,
//     compensating for the trigger being weaker evidence of "this is a
//     secret position" than api_key/password: with a noisier trigger, the
//     value itself has to look more convincingly random.
//   - RejectUUID and RejectDigits are true (tokens are rarely bare UUIDs
//     or bare digit runs in practice), but RejectHexHash is deliberately
//     left false: long hex strings ("token: deadbeef...") are a common
//     enough real bearer/session token shape that structurally rejecting
//     all hex would defeat the rule's purpose.
//   - MaxRepeatRun is left at 0 (disabled): unlike the tight assignment
//     preset, this preset relies on IsPlaceholder plus the entropy floor
//     alone to catch placeholder-shaped tokens.
var PresetLooseToken = Options{
	MinLen:         16,
	MaxLen:         256,
	MinBitsPerByte: 3.7,
	RejectUUID:     true,
	RejectDigits:   true,
}

// PresetDeepGenericValue is the Options used by the deep-profile-only
// generic-secret-assignment rule (GenericSecretAssignment, internal/rules/
// validators/genericdeep.go). That rule's keyword surface (bare "key",
// "secret", "auth", "access", "credential", "creds") is deliberately
// broader — and so weaker evidence of a secret position — than any of
// the three balanced-profile generic rules' own keywords: the entire
// point of the rule is to catch assignments those narrower, specific
// keywords miss (e.g. "AWS Secret Key = ..." contains no literal
// "secret_key" substring). To compensate for that weaker context:
//   - MinBitsPerByte of 3.7 matches PresetLooseToken's own compensation
//     for a weak, generic trigger.
//   - MinLen of 16 and MaxLen of 128 are the same general bounds
//     PresetAssignmentValue and PresetLooseToken already use for this
//     shape of credential value.
//   - RejectHexHash is left false, for the same reason PresetLooseToken
//     leaves it false: long hex strings are a common real session/auth
//     token shape, and structurally rejecting all hex here would defeat
//     a meaningful fraction of what this broader rule exists to catch.
//   - RejectUUID and RejectDigits stay true: a bare UUID or digit run is
//     essentially never the secret value itself in this position.
//   - MaxRepeatRun of 4 catches placeholder runs the same way
//     PresetAssignmentValue's does.
var PresetDeepGenericValue = Options{
	MinLen:         16,
	MaxLen:         128,
	MinBitsPerByte: 3.7,
	RejectUUID:     true,
	RejectDigits:   true,
	MaxRepeatRun:   4,
}

// Secretlike reports whether b plausibly looks like a secret under o: it
// checks length bounds, rejects well-known placeholder values (see
// IsPlaceholder), rejects long identical-byte runs (see
// Options.MaxRepeatRun), rejects the byte-shape classes o opts into
// rejecting (see Options.RejectUUID/RejectHexHash/RejectDigits), always
// rejects word-like values (ClassWordlike, by construction never a
// plausible secret), and finally requires Shannon(b) to reach
// o.MinBitsPerByte (when set).
//
// Secretlike is a heuristic, not a proof: it is tuned to a false-positive
// budget (see internal/rules/validators/generic.go), not to certainty.
func Secretlike(b []byte, o Options) bool {
	n := len(b)
	if o.MinLen > 0 && n < o.MinLen {
		return false
	}
	if o.MaxLen > 0 && n > o.MaxLen {
		return false
	}
	if IsPlaceholder(b) {
		return false
	}
	if o.MaxRepeatRun > 0 && longestRepeatRun(b) > o.MaxRepeatRun {
		return false
	}

	// classifyEntropy reports Shannon(b) as a byproduct when the wordlike
	// check already computed it, so the MinBitsPerByte check below can
	// reuse it instead of scanning b for entropy a second time.
	class, entropy, entropyComputed := classifyEntropy(b)
	switch class {
	case ClassWordlike:
		// Word-like values are never secretlike, independent of o: the
		// class itself is defined as "low entropy relative to its
		// alphabet", so there is no threshold at which one becomes a
		// plausible secret.
		return false
	case ClassUUID:
		if o.RejectUUID {
			return false
		}
	case ClassHexHash:
		if o.RejectHexHash {
			return false
		}
	case ClassDigits:
		if o.RejectDigits {
			return false
		}
	}

	if o.MinBitsPerByte > 0 {
		if !entropyComputed {
			entropy = Shannon(b)
		}
		if entropy < o.MinBitsPerByte {
			return false
		}
	}
	return true
}

// longestRepeatRun returns the length of the longest run of identical
// consecutive bytes in b. longestRepeatRun(nil) is 0.
func longestRepeatRun(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	best, run := 1, 1
	for i := 1; i < len(b); i++ {
		if b[i] == b[i-1] {
			run++
			if run > best {
				best = run
			}
		} else {
			run = 1
		}
	}
	return best
}
