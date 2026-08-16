package entropy

import "github.com/lastpersonlabs/goredact/internal/ahocorasick"

// substringPlaceholders are lowercase keywords that mark b as a
// placeholder if they appear ANYWHERE in b (case-insensitively).
var substringPlaceholders = []string{
	"example",
	"changeme",
	"change_me",
	"password",
	"your-",
	"your_",
	"placeholder",
	"dummy",
	"sample",
	"test",
	"todo",
	"xxxx",
	"0000",
	"1234",
	"abcd",
	"redact",
	"hunter2",
	"abc123",
	"a1b2c3",
	"_here",
}

// wholeValuePlaceholders are lowercase keywords that mark b as a
// placeholder only when they equal b exactly (case-insensitively): these
// are common enough as substrings of real-looking secrets that a bare
// substring match would be too aggressive.
var wholeValuePlaceholders = []string{
	"secret",
}

// keyboardRuns are lowercase keyboard-row sequences that mark b as a
// placeholder if they appear anywhere in b (case-insensitively), in
// addition to the ascending-run check in isAscendingRun.
var keyboardRuns = []string{
	"qwerty",
	"asdfgh",
	"zxcvbn",
	"qazwsx",
}

// anywhereKeywordAutomaton is a single compiled automaton over every
// keyword in substringPlaceholders and keyboardRuns (all matched
// case-insensitively), built once at package init. IsPlaceholder used to
// check these ~24 keywords with one independent O(len(b)) containsFold
// scan each; scanning b through this automaton once instead reaches the
// same true/false outcome (the two source lists are only ever consulted
// for "does any of these occur anywhere", never for which one matched) in
// a single O(len(b)) pass.
var anywhereKeywordAutomaton = mustCompileAnywhereKeywords()

func mustCompileAnywhereKeywords() *ahocorasick.Automaton {
	patterns := make([]ahocorasick.Pattern, 0, len(substringPlaceholders)+len(keyboardRuns))
	for _, kw := range substringPlaceholders {
		patterns = append(patterns, ahocorasick.Pattern{Literal: kw, CaseFold: true})
	}
	for _, kw := range keyboardRuns {
		patterns = append(patterns, ahocorasick.Pattern{Literal: kw, CaseFold: true})
	}
	a, err := ahocorasick.Compile(patterns)
	if err != nil {
		// substringPlaceholders/keyboardRuns are fixed, non-empty literal
		// lists baked into this package; a Compile failure here can only
		// mean a programmer error (e.g. an empty literal added to one of
		// them), not a runtime data condition.
		panic("entropy: failed to compile placeholder keyword automaton: " + err.Error())
	}
	return a
}

// containsAnywhereKeyword reports whether any keyword from
// substringPlaceholders or keyboardRuns occurs anywhere in b,
// case-insensitively, in one pass over b.
func containsAnywhereKeyword(b []byte) bool {
	found := false
	anywhereKeywordAutomaton.Scan(0, b, func(pattern, end int) bool {
		found = true
		return false // first match is enough; stop scanning.
	})
	return found
}

// IsPlaceholder reports whether b is a well-known non-secret stand-in
// value rather than real secret material: common keyword placeholders
// ("example", "changeme", "password", ...), angle-bracket tokens
// ("<REDACTED>"), template and variable references ("${VAR}", "$VAR",
// "{token}", "{{ var }}"), a single byte repeated for the whole value,
// and ascending or keyboard-row runs ("abcdef...", "123456...",
// "qwerty...").
//
// IsPlaceholder is deliberately permissive about what counts as a
// placeholder — false positives here (a real secret misclassified as a
// placeholder) are the cost of catching the extremely common
// documentation/fixture/config-template values that would otherwise
// dominate a naive entropy-only detector's false-positive rate. It is
// byte-oriented and allocation-free — validators call it once per
// candidate on the streaming hot path — and it never panics regardless
// of b's contents, including nil or empty.
func IsPlaceholder(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if isSingleRepeatedByte(b) {
		return true
	}
	if isAngleBracketToken(b) {
		return true
	}
	if isTemplateRef(b) {
		return true
	}
	if isAscendingRun(b) {
		return true
	}
	if containsAnywhereKeyword(b) {
		return true
	}
	for _, kw := range wholeValuePlaceholders {
		if len(b) == len(kw) && matchFoldAt(b, 0, kw) {
			return true
		}
	}
	return false
}

// isSingleRepeatedByte reports whether every byte in b is identical to the
// first (length 1 counts as trivially repeated).
func isSingleRepeatedByte(b []byte) bool {
	for _, c := range b[1:] {
		if c != b[0] {
			return false
		}
	}
	return true
}

// isAngleBracketToken reports whether b is wrapped in a single pair of
// angle brackets, e.g. "<REDACTED>" or "<your-api-key>": a documentation
// convention for "put your value here", never a real secret.
func isAngleBracketToken(b []byte) bool {
	return len(b) >= 2 && b[0] == '<' && b[len(b)-1] == '>'
}

// isTemplateRef reports whether b is a template or shell-variable
// reference rather than a literal secret value: "${VAR}", "$(cmd)", a
// bare "$IDENTIFIER" shell variable, or a value wrapped in braces
// ("{token}", "{{ secrets.token }}").
//
// A leading '$' alone is not sufficient: modular-crypt-format password
// hashes — "$2b$12$..." (bcrypt), "$argon2id$v=19$..." (argon2), "$6$..."
// (sha512crypt) — also start with '$', and are exactly the kind of value
// the contextual "password = ..." rules need to redact, not wave through
// as a placeholder. Those formats are distinguished by their rigid
// grammar: 2 or more further '$' field separators after the leading one,
// which a shell reference never has. Only a value with fewer than 2
// further '$' bytes (and not itself a "${...}"/"$(...)" wrapper) is
// treated as a template/variable reference.
func isTemplateRef(b []byte) bool {
	if len(b) >= 1 && b[0] == '$' {
		if len(b) >= 3 && b[1] == '{' && b[len(b)-1] == '}' {
			return true
		}
		if len(b) >= 3 && b[1] == '(' && b[len(b)-1] == ')' {
			return true
		}
		return countByte(b[1:], '$') < 2
	}
	if len(b) >= 3 && b[0] == '{' && b[len(b)-1] == '}' {
		return true
	}
	return false
}

// countByte returns the number of times c occurs in b.
func countByte(b []byte, c byte) int {
	n := 0
	for _, x := range b {
		if x == c {
			n++
		}
	}
	return n
}

// isAscendingRun reports whether b contains a run of 4 or more
// case-folded consecutive bytes each one greater than the last by
// exactly 1, e.g. "abcdef", "ABCDef", or "34567": a keyboard/counting
// pattern used in throwaway example values, essentially never present
// in a random secret of any length worth flagging.
func isAscendingRun(b []byte) bool {
	run := 1
	for i := 1; i < len(b); i++ {
		if lowerASCII(b[i]) == lowerASCII(b[i-1])+1 {
			run++
			if run >= 4 {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

// lowerASCII folds ASCII 'A'-'Z' to lowercase; all other bytes pass
// through unchanged.
func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		c = c - 'A' + 'a'
	}
	return c
}

// matchFoldAt reports whether haystack[pos:pos+len(needle)] equals
// needle ignoring ASCII case. needle must already be lowercase ASCII.
func matchFoldAt(haystack []byte, pos int, needle string) bool {
	for j := 0; j < len(needle); j++ {
		if lowerASCII(haystack[pos+j]) != needle[j] {
			return false
		}
	}
	return true
}
