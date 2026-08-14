package entropy

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
	for _, kw := range keyboardRuns {
		if containsFold(b, kw) {
			return true
		}
	}
	for _, kw := range substringPlaceholders {
		if containsFold(b, kw) {
			return true
		}
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
// reference rather than a literal secret value: any value starting with
// '$' ("$GITHUB_TOKEN", "${API_KEY}" — no real secret alphabet includes
// a leading dollar sign), or a value wrapped in braces ("{token}",
// "{{ secrets.token }}").
func isTemplateRef(b []byte) bool {
	if len(b) >= 1 && b[0] == '$' {
		return true
	}
	if len(b) >= 3 && b[0] == '{' && b[len(b)-1] == '}' {
		return true
	}
	return false
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

// containsFold reports whether needle (which must already be lowercase
// ASCII) occurs anywhere in haystack, ignoring ASCII case. Folding
// during comparison keeps this allocation-free on the per-candidate
// hot path.
func containsFold(haystack []byte, needle string) bool {
	n := len(needle)
	if n == 0 {
		return true
	}
	for i := 0; i+n <= len(haystack); i++ {
		if matchFoldAt(haystack, i, needle) {
			return true
		}
	}
	return false
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
