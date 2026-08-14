// Validators for payments, messaging, and project-management provider
// credentials (ENG-111): Stripe, Slack (user/app tokens — bot tokens are
// the pre-existing SlackBotToken in validators.go), SendGrid, Twilio,
// Linear, and Notion.
//
// All functions here follow the same contract as validators.go: pure,
// window-relative, byte-only, never panic regardless of how the window is
// truncated relative to the trigger or the rule's configured lookaround.
package validators

// isURLSafeChar reports whether c is a byte that may appear in a
// URL-safe-base64-ish token segment: ASCII letters, digits, underscore, or
// hyphen. SendGrid API keys are drawn from this alphabet.
func isURLSafeChar(c byte) bool {
	return isAlnum(c) || c == '_' || c == '-'
}

// allURLSafe reports whether every byte in b is an isURLSafeChar byte. An
// empty slice is not all-URL-safe (there is nothing to confirm), mirroring
// allAlnum's treatment of empty input.
func allURLSafe(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !isURLSafeChar(c) {
			return false
		}
	}
	return true
}

// urlSafeBoundaryOK is boundaryOK's counterpart for tokens drawn from the
// isURLSafeChar alphabet (which includes '_' and '-', so plain boundaryOK's
// alnum-only check would wrongly treat a token immediately followed by more
// underscore/hyphen characters as a clean boundary).
func urlSafeBoundaryOK(window []byte, pos int) bool {
	if pos >= len(window) {
		return true
	}
	return !isURLSafeChar(window[pos])
}

// isLowerHex reports whether c is an ASCII lowercase hex digit.
func isLowerHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f')
}

// allLowerHex reports whether every byte in b is an isLowerHex byte. An
// empty slice is not all-lower-hex, mirroring allAlnum.
func allLowerHex(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !isLowerHex(c) {
			return false
		}
	}
	return true
}

// precededByIdentByte reports whether the byte immediately before
// window[trigStart], if any, would continue an identifier: an ASCII
// alphanumeric character or underscore. It is the mirror image of
// boundaryOK, used by triggers ("SG.", "SK", "secret_") short or generic
// enough that they occur as substrings of unrelated identifiers
// (client_secret_, TASKS, DESK, MSG.) — those occurrences must be rejected
// even though the trigger literal matched.
func precededByIdentByte(window []byte, trigStart int) bool {
	if trigStart <= 0 {
		return false
	}
	c := window[trigStart-1]
	return isAlnum(c) || c == '_'
}

// StripeSecretKey confirms a Stripe secret/restricted API key: one of the
// triggers "sk_live_", "sk_test_", "rk_live_", "rk_test_" followed by
// 24-99 ASCII alphanumeric characters and a non-alphanumeric byte (or end
// of window). Test-mode keys (sk_test_/rk_test_) are still credentials —
// they authenticate against Stripe's test-mode API — so they are redacted
// identically to live-mode keys.
func StripeSecretKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	bodyEnd, ok := consumeAlnumRun(window, trigEnd, 24, 99)
	if !ok {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	if allSame(window[trigEnd:bodyEnd]) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// StripeWebhookSecret confirms a Stripe webhook signing secret: trigger
// "whsec_" followed by 32-64 ASCII alphanumeric characters and a
// non-alphanumeric byte (or end of window).
func StripeWebhookSecret(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	bodyEnd, ok := consumeAlnumRun(window, trigEnd, 32, 64)
	if !ok {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	if allSame(window[trigEnd:bodyEnd]) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// SlackUserToken confirms a Slack user-scoped token: one of the triggers
// "xoxp-", "xoxa-", "xoxr-", "xoxs-" followed by <10-13 digits>-<10-13
// digits>-<24-34 alphanumeric characters>. xoxp tokens historically carry
// an extra digit group before that final segment
// (<digits>-<digits>-<digits>-<alnum>); both the two-group and three-group
// shapes are accepted for all four prefixes, since the distinguishing
// factor is workspace/token vintage, not which of these four prefixes was
// used. The three-group shape is tried first (it is the more specific
// match); when it doesn't validate, the parser falls back to treating the
// segment right after the second dash as the final alphanumeric run
// directly.
func SlackUserToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	pos, ok := consumeDigitRun(window, trigEnd, 10, 13)
	if !ok {
		return 0, 0, false
	}
	pos, ok = consumeByte(window, pos, '-')
	if !ok {
		return 0, 0, false
	}
	pos, ok = consumeDigitRun(window, pos, 10, 13)
	if !ok {
		return 0, 0, false
	}
	pos, ok = consumeByte(window, pos, '-')
	if !ok {
		return 0, 0, false
	}

	// Three-group shape: another <digits>- before the final segment.
	if p, ok3 := consumeDigitRun(window, pos, 10, 13); ok3 {
		if p, ok3 = consumeByte(window, p, '-'); ok3 {
			if segEnd, okSeg := consumeAlnumRun(window, p, 24, 34); okSeg {
				if boundaryOK(window, segEnd) && !allSame(window[p:segEnd]) {
					return trigStart, segEnd, true
				}
			}
		}
	}

	// Two-group shape: the final segment starts right after the second
	// dash.
	if segEnd, okSeg := consumeAlnumRun(window, pos, 24, 34); okSeg {
		if boundaryOK(window, segEnd) && !allSame(window[pos:segEnd]) {
			return trigStart, segEnd, true
		}
	}

	return 0, 0, false
}

// SlackAppToken confirms a Slack app-level token: trigger "xapp-" followed
// by a run of 40-100 bytes drawn from [A-Za-z0-9-] containing at least 3
// hyphens, and a non-alphanumeric byte (or end of window). Slack's
// documented shape is <digit>-<10-12 char alnum segment>-<10-13
// digits>-<64 hex chars>, but this validator deliberately accepts the
// looser digit/dash/token-char envelope rather than pinning every segment
// length, so it isn't invalidated by minor token-format revisions.
func SlackAppToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	pos := trigEnd
	dashes := 0
	for pos < len(window) && (isAlnum(window[pos]) || window[pos] == '-') {
		if window[pos] == '-' {
			dashes++
		}
		pos++
	}
	n := pos - trigEnd
	if n < 40 || n > 100 {
		return 0, 0, false
	}
	if dashes < 3 {
		return 0, 0, false
	}
	if !boundaryOK(window, pos) {
		return 0, 0, false
	}
	if allSame(window[trigEnd:pos]) {
		return 0, 0, false
	}
	return trigStart, pos, true
}

// SendGridAPIKey confirms a SendGrid API key: trigger "SG." preceded by a
// non-identifier byte (or start of window) — this trigger is a substring
// of ordinary words like "MSG." (a message-related identifier), so a
// preceding letter/digit/underscore means this "SG." occurrence is part of
// a longer identifier, not a key — followed by exactly 22
// [A-Za-z0-9_-] characters, a literal '.', exactly 43 more
// [A-Za-z0-9_-] characters, and a byte outside that alphabet (or end of
// window).
func SendGridAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if precededByIdentByte(window, trigStart) {
		return 0, 0, false
	}

	seg1End := trigEnd + 22
	if seg1End > len(window) {
		return 0, 0, false
	}
	seg1 := window[trigEnd:seg1End]
	if !allURLSafe(seg1) {
		return 0, 0, false
	}
	// If the true urlSafe run starting at trigEnd is longer than 22 bytes,
	// window[seg1End] is itself still a urlSafe character rather than the
	// literal '.' a well-formed key requires there, so this check alone
	// (with no separate "is the run longer than 22" check needed) rejects
	// both a too-short and a too-long first segment.
	if seg1End >= len(window) || window[seg1End] != '.' {
		return 0, 0, false
	}
	pos := seg1End + 1

	seg2End := pos + 43
	if seg2End > len(window) {
		return 0, 0, false
	}
	seg2 := window[pos:seg2End]
	if !allURLSafe(seg2) {
		return 0, 0, false
	}
	if !urlSafeBoundaryOK(window, seg2End) {
		return 0, 0, false
	}
	if allSame(seg2) {
		return 0, 0, false
	}
	return trigStart, seg2End, true
}

// TwilioAPIKeySID confirms a Twilio API key SID: trigger "SK" (matched
// case-sensitively — see the rule spec) preceded by a non-identifier byte
// (or start of window) — "SK" is a substring of ordinary words like "TASK"
// and "DESK", so a preceding letter/digit/underscore means this isn't a
// standalone SID — followed by exactly 32 ASCII lowercase hex characters
// and a non-alphanumeric byte (or end of window).
func TwilioAPIKeySID(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if precededByIdentByte(window, trigStart) {
		return 0, 0, false
	}

	bodyEnd := trigEnd + 32
	if bodyEnd > len(window) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if !allLowerHex(body) {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	if allSame(body) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// LinearAPIKey confirms a Linear personal API key: trigger "lin_api_"
// followed by 40-60 ASCII alphanumeric characters and a non-alphanumeric
// byte (or end of window).
func LinearAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	bodyEnd, ok := consumeAlnumRun(window, trigEnd, 40, 60)
	if !ok {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	if allSame(window[trigEnd:bodyEnd]) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// NotionInternalToken confirms a Notion internal integration token, in
// either of its two documented forms:
//
//   - trigger "secret_" preceded by a non-identifier byte (or start of
//     window) — this trigger is a substring of the common identifier
//     "client_secret_" (an OAuth client secret field name, not a Notion
//     token), so a preceding letter/digit/underscore means this occurrence
//     isn't a standalone token — followed by exactly 43 ASCII
//     alphanumeric characters.
//   - trigger "ntn_" followed by 46-60 ASCII alphanumeric characters.
//
// Both forms require a non-alphanumeric byte (or end of window) after the
// body. Which shape is being validated is determined by trigEnd-trigStart
// (7 for "secret_", 4 for "ntn_"), since that's all that distinguishes the
// two triggers from inside a validator that only sees window-relative
// offsets.
func NotionInternalToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	switch trigEnd - trigStart {
	case len("secret_"):
		if precededByIdentByte(window, trigStart) {
			return 0, 0, false
		}
		bodyEnd := trigEnd + 43
		if bodyEnd > len(window) {
			return 0, 0, false
		}
		body := window[trigEnd:bodyEnd]
		if !allAlnum(body) {
			return 0, 0, false
		}
		if !boundaryOK(window, bodyEnd) {
			return 0, 0, false
		}
		if allSame(body) {
			return 0, 0, false
		}
		return trigStart, bodyEnd, true

	case len("ntn_"):
		bodyEnd, ok := consumeAlnumRun(window, trigEnd, 46, 60)
		if !ok {
			return 0, 0, false
		}
		if !boundaryOK(window, bodyEnd) {
			return 0, 0, false
		}
		if allSame(window[trigEnd:bodyEnd]) {
			return 0, 0, false
		}
		return trigStart, bodyEnd, true

	default:
		return 0, 0, false
	}
}
