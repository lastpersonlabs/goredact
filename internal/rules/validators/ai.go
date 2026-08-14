package validators

import "bytes"

// This file holds validators for AI-platform provider secrets from
// Anthropic, OpenAI (project-scoped and legacy),
// Hugging Face, and Groq API keys. See validators.go for the shared
// ValidateFunc contract and low-level byte helpers (isAlnum, allAlnum,
// isPlaceholder, boundaryOK, consumeByte, consumeDigitRun, consumeAlnumRun) that
// these validators build on.
//
// Google's "AIza..." API key shape is intentionally NOT implemented here;
// it belongs to the cloud-provider validator set.

// isAlnumExt reports whether c is an ASCII letter, digit, hyphen, or
// underscore — the character class used by the body of Anthropic and
// OpenAI project-scoped keys, which (unlike the classic GitHub/Slack/
// Hugging Face/Groq token bodies) legitimately contain '-' and '_'.
func isAlnumExt(c byte) bool {
	return isAlnum(c) || c == '-' || c == '_'
}

// consumeExtRun consumes the maximal run of isAlnumExt bytes starting at
// pos and reports the end offset if its length is within [min, max]. Like
// consumeAlnumRun, a maximal run longer than max is rejected outright
// (there is no non-arbitrary shorter cut that would leave a valid
// boundary), and it never indexes out of range.
func consumeExtRun(window []byte, pos, min, max int) (end int, ok bool) {
	start := pos
	for pos < len(window) && isAlnumExt(window[pos]) {
		pos++
	}
	n := pos - start
	if n < min || n > max {
		return pos, false
	}
	return pos, true
}

// precedingBoundaryOK reports whether the byte immediately before pos in
// window, if any, does not continue an alphanumeric run — the mirror image
// of boundaryOK, used to confirm a trigger isn't a suffix of a longer
// identifier or word (e.g. the "sk-ant-" in "risk-ant-eater").
func precedingBoundaryOK(window []byte, pos int) bool {
	if pos <= 0 {
		return true
	}
	return !isAlnum(window[pos-1])
}

// precedingBoundaryExtOK is precedingBoundaryOK extended to also reject a
// preceding '-' or '_', for tokens whose trigger is short and generic
// enough (bare "sk-") that a preceding hyphen/underscore still plausibly
// means "this is part of a larger token", not a real boundary.
func precedingBoundaryExtOK(window []byte, pos int) bool {
	if pos <= 0 {
		return true
	}
	return !isAlnumExt(window[pos-1])
}

// hasRepeatRun reports whether b contains a run of n or more consecutive
// identical bytes. Real high-entropy secrets essentially never contain
// such runs; placeholder/redacted fixtures ("xxxxxxxxxxxx...") commonly
// do, so this is used alongside isPlaceholder to catch placeholders that are
// only partially repeated (e.g. a real-looking prefix/suffix wrapped
// around a long run of 'x').
func hasRepeatRun(b []byte, n int) bool {
	if n <= 0 || len(b) < n {
		return false
	}
	run := 1
	for i := 1; i < len(b); i++ {
		if b[i] == b[i-1] {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

// AnthropicAPIKey confirms the Anthropic API key shape: trigger "sk-ant-"
// followed by 80-130 bytes of [A-Za-z0-9_-] (this covers both the common
// "api03-"/"admin01-"-style sub-segment plus the ~80-120 character body,
// since that sub-segment's own alphabet is a subset of the body's, and the
// literal "sk-ant-" prefix's total post-prefix length is what's actually
// bounded). Real Anthropic keys are never shorter than ~100 characters
// after the prefix; the 80 floor rejects the short fabricated
// "sk-ant-api03-<32-40 chars>" keys that dominate documentation and test
// fixtures. It also rejects placeholder bodies (all one character, or any
// long repeated run) and requires a non-alphanumeric byte (or end of
// window) on both sides.
func AnthropicAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	bodyEnd, ok2 := consumeExtRun(window, trigEnd, 80, 130)
	if !ok2 {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if isPlaceholder(body) || hasRepeatRun(body, 5) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// openAIInfix is the fixed "T3BlbkFJ" substring (base64 of "OpenAI"
// shifted by the key-format framing OpenAI uses) that appears in both
// legacy and project-scoped OpenAI keys.
var openAIInfix = []byte("T3BlbkFJ")

// openAIProjectExclusions lists the byte sequences that, if found
// immediately after a bare "sk-" trigger, mean the match belongs to a
// different, more specific rule (openai-project-key or anthropic-api-key)
// and must not be confirmed by openai-legacy-key.
var openAIProjectExclusions = [][]byte{
	[]byte("ant-"),
	[]byte("proj-"),
	[]byte("svcacct-"),
	[]byte("admin-"),
}

// OpenAIProjectKey confirms the OpenAI project-scoped key shapes: trigger
// "sk-proj-", "sk-svcacct-", or "sk-admin-" followed by [A-Za-z0-9_-].
// The body must be at least 40 bytes and at most 200. If it contains the
// "T3BlbkFJ" infix anywhere, it is confirmed regardless of length beyond
// that floor/ceiling; without the infix, it must additionally be at least
// 48 bytes and not look like a placeholder (all one character, or a long
// repeated run).
func OpenAIProjectKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	bodyEnd, ok2 := consumeExtRun(window, trigEnd, 40, 200)
	if !ok2 {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if bytes.Contains(body, openAIInfix) {
		return trigStart, bodyEnd, true
	}
	if len(body) < 48 {
		return 0, 0, false
	}
	if isPlaceholder(body) || hasRepeatRun(body, 5) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// OpenAILegacyKey confirms the classic OpenAI secret key shape: trigger
// "sk-" followed by exactly 20 [A-Za-z0-9], the literal infix "T3BlbkFJ",
// then exactly 20 more [A-Za-z0-9] (48 bytes total), with a
// non-alphanumeric byte (or end of window) on the right and a byte that is
// not [A-Za-z0-9_-] (or start of window) on the left.
//
// Because "sk-" is a substring of "sk-ant-", "sk-proj-", "sk-svcacct-",
// and "sk-admin-", this validator explicitly refuses to confirm when the
// bytes immediately after the trigger begin with any of those other
// rules' distinguishing suffixes — those occurrences belong to
// anthropic-api-key or openai-project-key instead.
func OpenAILegacyKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryExtOK(window, trigStart) {
		return 0, 0, false
	}

	rest := window[trigEnd:]
	for _, excl := range openAIProjectExclusions {
		if bytes.HasPrefix(rest, excl) {
			return 0, 0, false
		}
	}

	const (
		segLen   = 20
		infixLen = 8
		total    = segLen + infixLen + segLen
	)
	bodyEnd := trigEnd + total
	if bodyEnd > len(window) {
		return 0, 0, false
	}
	first := window[trigEnd : trigEnd+segLen]
	infix := window[trigEnd+segLen : trigEnd+segLen+infixLen]
	last := window[trigEnd+segLen+infixLen : bodyEnd]

	if !allAlnum(first) || !allAlnum(last) {
		return 0, 0, false
	}
	if !bytes.Equal(infix, openAIInfix) {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	if isPlaceholder(first) || isPlaceholder(last) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// HuggingFaceToken confirms the Hugging Face token shape: trigger "hf_"
// followed by exactly 34 [A-Za-z0-9] and a non-alphanumeric byte (or end
// of window). Identifiers like "hf_hub_download" are naturally excluded:
// the underscore after "hub" ends the alphanumeric run well short of 34.
func HuggingFaceToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	const tokenLen = 34
	bodyEnd, ok2 := consumeAlnumRun(window, trigEnd, tokenLen, tokenLen)
	if !ok2 {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if isPlaceholder(body) || hasRepeatRun(body, 8) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// GroqAPIKey confirms the Groq API key shape: trigger "gsk_" followed by
// exactly 52 [A-Za-z0-9] and a non-alphanumeric byte (or end of window).
func GroqAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if !precedingBoundaryOK(window, trigStart) {
		return 0, 0, false
	}
	const tokenLen = 52
	bodyEnd, ok2 := consumeAlnumRun(window, trigEnd, tokenLen, tokenLen)
	if !ok2 {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if isPlaceholder(body) || hasRepeatRun(body, 8) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}
