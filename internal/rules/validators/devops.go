// This file implements CI/devops provider credential validators: CircleCI
// personal/project API tokens, Buildkite API access tokens, Datadog API
// and Application keys, Grafana service-account and cloud-access-policy
// tokens, Doppler tokens, and Vercel access tokens. Each function follows
// the same contract as the seed validators in validators.go: pure,
// panic-free functions of window that report a window-relative half-open
// span to redact.
//
// Several of these providers (Buildkite, Datadog, and legacy Vercel
// tokens) issue bare fixed-length alphanumeric/hex values with no
// in-token prefix at all — the same shape as a git commit SHA or an MD5
// hash. Per docs/RULE_AUTHORING.md, a generic value shape like that needs
// additional context to be a safe deterministic rule, so these are
// implemented as contextual assignments keyed on the provider's own
// documented environment-variable name (the same design AWSSecretAccessKey,
// cloud.go, already uses for AWS's equally prefix-less secret access key).
//
// CircleCI and Vercel each still have an older, bare, prefix-less token
// format in circulation (a 40-character hex string for CircleCI, a
// 24-character alphanumeric string for legacy Vercel). CircleCI's legacy
// format has no distinguishing context at all — the exact same shape as a
// git SHA-1 and, separately, a Buildkite token — so it is deliberately
// not matched here rather than risk a high false-positive rule; Vercel's
// legacy format is covered by VercelLegacyToken below since it does have
// a well-documented env var to key off.
package validators

// consumeAssignedValue confirms the shape of a value assigned to a
// trigger key name (matched by the caller's trigger literal, so the
// trigger itself is never part of the returned span): optional spaces, a
// '=' or ':' separator, optional spaces, an optional opening quote,
// exactly length characters satisfying pred, a matching closing quote if
// one was opened, and a boundary (pred must not continue past the
// value). It rejects placeholder values. This is the same
// separator/quote/boundary handling AWSSecretAccessKey (cloud.go) uses
// for AWS's own prefix-less secret access key, generalized for reuse
// across the prefix-less CI/devops token shapes in this file.
func consumeAssignedValue(window []byte, trigEnd, length int, pred func(byte) bool) (start, end int, ok bool) {
	pos := skipSpaces(window, trigEnd)
	// A JSON-style quoted key ("dd_api_key": ...) leaves its own closing
	// quote directly after the trigger; skip at most one such quote byte
	// before looking for the separator. Unquoted keys (YAML, shell, .env)
	// simply won't have one here, so this is a no-op for them.
	if pos < len(window) && (window[pos] == '"' || window[pos] == '\'') {
		pos++
		pos = skipSpaces(window, pos)
	}
	if pos >= len(window) {
		return 0, 0, false
	}
	if window[pos] != '=' && window[pos] != ':' {
		return 0, 0, false
	}
	pos++
	pos = skipSpaces(window, pos)

	var quote byte
	if pos < len(window) && (window[pos] == '"' || window[pos] == '\'') {
		quote = window[pos]
		pos++
	}

	valStart := pos
	valEnd := valStart + length
	if valEnd > len(window) {
		return 0, 0, false
	}
	value := window[valStart:valEnd]
	for _, c := range value {
		if !pred(c) {
			return 0, 0, false
		}
	}

	after := valEnd
	if quote != 0 {
		if after >= len(window) || window[after] != quote {
			return 0, 0, false
		}
	} else if after < len(window) && pred(window[after]) {
		return 0, 0, false
	}

	if isPlaceholder(value) {
		return 0, 0, false
	}
	return valStart, valEnd, true
}

// --- CircleCI personal/project API token -----------------------------

// circleCIUUIDMin and circleCIUUIDMax bound the length of the base58 UUID
// segment between a CircleCI token's prefix and its trailing hex
// checksum-like segment. CircleCI does not publish an exact contract for
// this segment's length; every reproduction of the shape converges on
// "about 22 characters," so this range has a little slack on both ends.
const (
	circleCIUUIDMin = 20
	circleCIUUIDMax = 24
)

// circleCIHexLen is the fixed length of the trailing hex segment of a
// CircleCI token, unchanged from the legacy bare-token format CircleCI
// used before introducing the CCIPAT_/CCIPRJ_ prefixes.
const circleCIHexLen = 40

// isBase58 reports whether c belongs to the base58 alphabet (alphanumeric
// minus '0', 'O', 'I', and 'l', the four characters base58 excludes to
// avoid visual ambiguity), the alphabet CircleCI uses to encode the UUID
// segment of its token.
func isBase58(c byte) bool {
	switch c {
	case '0', 'O', 'I', 'l':
		return false
	}
	return isAlnum(c)
}

// CircleCIToken confirms the current CircleCI personal/project API token
// shape: trigger "CCIPAT_" (personal) or "CCIPRJ_" (project), followed by
// a 20-24 character base58 UUID segment, a literal '_', and a fixed
// 40-character lowercase hex segment. CircleCI's older bare 40-character
// hex tokens (personal and project tokens were the same shape) are not
// matched by any rule here: that shape has no distinguishing context at
// all, identical to a git SHA-1 hash or a Buildkite token, so a
// deterministic rule for it would carry an unacceptable false-positive
// rate.
//
// https://circleci.com/changelog/new-format-for-api-access-tokens
// https://circleci.com/docs/managing-api-tokens/
func CircleCIToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	uuidEnd, ok := consumeRun(window, trigEnd, circleCIUUIDMin, circleCIUUIDMax, isBase58)
	if !ok {
		return 0, 0, false
	}
	pos, ok := consumeByte(window, uuidEnd, '_')
	if !ok {
		return 0, 0, false
	}
	hexEnd := pos + circleCIHexLen
	if hexEnd > len(window) {
		return 0, 0, false
	}
	hex := window[pos:hexEnd]
	if !allLowerHex(hex) {
		return 0, 0, false
	}
	if !boundaryOK(window, hexEnd) {
		return 0, 0, false
	}
	if isPlaceholder(window[trigEnd:uuidEnd]) || isPlaceholder(hex) {
		return 0, 0, false
	}
	return trigStart, hexEnd, true
}

// --- Buildkite API access token -----------------------------------------

// buildkiteTokenLen is the fixed length of a Buildkite API access token
// or agent token: a bare lowercase hex string with no prefix of its own.
const buildkiteTokenLen = 40

// BuildkiteAPIToken confirms the shape of a value assigned to
// BUILDKITE_API_TOKEN or BUILDKITE_AGENT_TOKEN (matched
// case-insensitively, the officially documented environment variable
// names for Buildkite's REST API token and agent registration token
// respectively): 40 characters of lowercase hex. Buildkite tokens have no
// fixed prefix of their own — identical in shape to a git SHA-1 hash —
// so this rule exists specifically for the documented variable-name
// context, per the file-level note above.
//
// https://buildkite.com/docs/apis/managing-api-tokens
// https://buildkite.com/docs/agent/v3/tokens
func BuildkiteAPIToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return consumeAssignedValue(window, trigEnd, buildkiteTokenLen, isLowerHex)
}

// --- Datadog API key and Application key ---------------------------------

// datadogAPIKeyLen and datadogAppKeyLen are the fixed lengths of
// Datadog's two bare hex credential types.
const (
	datadogAPIKeyLen = 32
	datadogAppKeyLen = 40
)

// DatadogAPIKey confirms the shape of a value assigned to DD_API_KEY
// (matched case-insensitively, Datadog's own documented Agent
// configuration variable): 32 characters of lowercase hex. Like
// Buildkite's token, a Datadog API key has no prefix of its own, so this
// rule is keyed on the documented variable name.
//
// https://docs.datadoghq.com/agent/guide/environment-variables/
func DatadogAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return consumeAssignedValue(window, trigEnd, datadogAPIKeyLen, isLowerHex)
}

// DatadogApplicationKey confirms the shape of a value assigned to
// DD_APP_KEY (matched case-insensitively, the variable name Datadog's own
// Terraform provider and CLI tooling document): 40 characters of
// lowercase hex.
//
// https://registry.terraform.io/providers/DataDog/datadog/latest/docs
func DatadogApplicationKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return consumeAssignedValue(window, trigEnd, datadogAppKeyLen, isLowerHex)
}

// --- Grafana service-account token and cloud access policy token --------

// grafanaSAKeyBodyLen and grafanaSAChecksumLen are the fixed lengths of a
// Grafana service-account token's two segments: an alphanumeric body and
// a trailing hex checksum.
const (
	grafanaSAKeyBodyLen  = 32
	grafanaSAChecksumLen = 8
)

// GrafanaServiceAccountToken confirms the Grafana service-account token
// shape: trigger "glsa_" followed by a fixed 32-character alphanumeric
// body, a literal '_', and a fixed 8-character hex checksum.
//
// https://grafana.com/docs/grafana/latest/administration/service-accounts/
func GrafanaServiceAccountToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	bodyEnd := trigEnd + grafanaSAKeyBodyLen
	if bodyEnd > len(window) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if !allAlnum(body) {
		return 0, 0, false
	}
	pos, ok := consumeByte(window, bodyEnd, '_')
	if !ok {
		return 0, 0, false
	}
	checksumEnd := pos + grafanaSAChecksumLen
	if checksumEnd > len(window) {
		return 0, 0, false
	}
	checksum := window[pos:checksumEnd]
	for _, c := range checksum {
		if !isHexByte(c) {
			return 0, 0, false
		}
	}
	if !boundaryOK(window, checksumEnd) {
		return 0, 0, false
	}
	if isPlaceholder(body) {
		return 0, 0, false
	}
	return trigStart, checksumEnd, true
}

// grafanaCloudTokenBodyMin and grafanaCloudTokenBodyMax bound the length
// of a Grafana Cloud access policy token's body: a base64-encoded JSON
// blob (the same {"k":...,"n":...,"id":...} shape as Grafana's legacy
// API keys, just prefixed). Grafana does not publish an exact length; a
// generous range covers what's been observed in the wild.
const (
	grafanaCloudTokenBodyMin = 32
	grafanaCloudTokenBodyMax = 400
)

// isGrafanaCloudTokenChar reports whether c belongs to the unpadded
// standard base64 alphabet [A-Za-z0-9/+] Grafana Cloud access policy
// tokens use for their body.
func isGrafanaCloudTokenChar(c byte) bool {
	return isAlnum(c) || c == '/' || c == '+'
}

// GrafanaCloudAccessPolicyToken confirms the Grafana Cloud access policy
// token shape: trigger "glc_" followed by 32-400 characters of standard
// base64 and up to two '=' padding characters.
//
// https://grafana.com/docs/grafana-cloud/account-management/authentication-and-permissions/access-policies/
func GrafanaCloudAccessPolicyToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	pos := trigEnd
	for pos < len(window) && isGrafanaCloudTokenChar(window[pos]) {
		pos++
	}
	bodyLen := pos - trigEnd
	if bodyLen < grafanaCloudTokenBodyMin || bodyLen > grafanaCloudTokenBodyMax {
		return 0, 0, false
	}
	body := window[trigEnd:pos]
	end = pos
	for pad := 0; pad < 2 && end < len(window) && window[end] == '='; pad++ {
		end++
	}
	if end < len(window) && (isGrafanaCloudTokenChar(window[end]) || window[end] == '=') {
		return 0, 0, false
	}
	if isPlaceholder(body) {
		return 0, 0, false
	}
	return trigStart, end, true
}

// --- Doppler token ---------------------------------------------------------

// dopplerTokenBodyMin and dopplerTokenBodyMax bound the length of a
// Doppler token's alphanumeric body, across every one of its seven scoped
// prefixes.
const (
	dopplerTokenBodyMin = 40
	dopplerTokenBodyMax = 44
)

// dopplerLabelMin and dopplerLabelMax bound the length of the optional
// config/environment label a service token (dp.st.) may carry between
// its prefix and its body, e.g. "dp.st.dev.<body>".
const (
	dopplerLabelMin = 2
	dopplerLabelMax = 35
)

// isDopplerLabelChar reports whether c belongs to the alphabet Doppler's
// documented token-format regex uses for a service token's optional
// config label ([a-z0-9\-_]): lowercase alphanumeric plus '-' and '_'.
func isDopplerLabelChar(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'z' || c == '-' || c == '_'
}

// DopplerToken confirms the Doppler token shape: one of seven scoped
// triggers ("dp.st.", "dp.pt.", "dp.ct.", "dp.sa.", "dp.said.",
// "dp.scim.", "dp.audit.") followed by a 40-44 character alphanumeric
// body. A service token (dp.st.) may additionally carry a single config
// label between the prefix and the body (e.g. "dp.st.dev.<body>"), per
// Doppler's own documented format regex
// (dp\.st\.(?:[a-z0-9\-_]{2,35}\.)?[a-zA-Z0-9]{40,44}); this is tried
// first, falling back to a bodyless-label match if the label candidate
// doesn't resolve to a valid body.
//
// https://docs.doppler.com/reference/auth-token-formats
func DopplerToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	labelEnd, labelOK := consumeRun(window, trigEnd, dopplerLabelMin, dopplerLabelMax, isDopplerLabelChar)
	if labelOK && labelEnd < len(window) && window[labelEnd] == '.' {
		bodyStart := labelEnd + 1
		if bodyEnd, ok := consumeRun(window, bodyStart, dopplerTokenBodyMin, dopplerTokenBodyMax, isAlnum); ok {
			if boundaryOK(window, bodyEnd) && !isPlaceholder(window[bodyStart:bodyEnd]) {
				return trigStart, bodyEnd, true
			}
		}
	}

	bodyEnd, ok := consumeRun(window, trigEnd, dopplerTokenBodyMin, dopplerTokenBodyMax, isAlnum)
	if !ok {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	if isPlaceholder(window[trigEnd:bodyEnd]) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// --- Vercel access token ----------------------------------------------------

// vercelTokenBodyMin and vercelTokenBodyMax bound the length of a current
// Vercel access token's alphanumeric body. Vercel does not publish an
// exact length across all five of its current prefixes; a 40-80
// character range comfortably covers the 56-character body its own docs
// show for personal access tokens without hard-coding that as the only
// valid length.
const (
	vercelTokenBodyMin = 40
	vercelTokenBodyMax = 80
)

// VercelToken confirms the current (2026+) Vercel access token shape: one
// of five scoped triggers ("vcp_" personal, "vci_" integration, "vca_"
// app access, "vcr_" app refresh, "vck_" API key) followed by 40-80
// alphanumeric characters.
//
// https://vercel.com/changelog/new-token-formats-and-secret-scanning
func VercelToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	bodyEnd, ok := consumeRun(window, trigEnd, vercelTokenBodyMin, vercelTokenBodyMax, isAlnum)
	if !ok {
		return 0, 0, false
	}
	if isPlaceholder(window[trigEnd:bodyEnd]) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// vercelLegacyTokenLen is the fixed length of a legacy (pre-2026) Vercel
// access token: a bare alphanumeric string with no prefix of its own.
const vercelLegacyTokenLen = 24

// VercelLegacyToken confirms the shape of a value assigned to
// VERCEL_TOKEN, VERCEL_API_TOKEN, or VERCEL_ACCESS_TOKEN (matched
// case-insensitively — VERCEL_TOKEN is Vercel's own documented CLI/REST
// API auth variable, the other two are common conventions seen alongside
// it): 24 alphanumeric characters. Tokens minted before Vercel introduced
// its current prefixed format remain valid and have no distinguishing
// shape of their own, so this rule is keyed on the documented variable
// names rather than the token body alone.
//
// https://vercel.com/docs/cli
// https://vercel.com/docs/rest-api
func VercelLegacyToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return consumeAssignedValue(window, trigEnd, vercelLegacyTokenLen, isAlnum)
}
