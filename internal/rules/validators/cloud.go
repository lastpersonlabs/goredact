package validators

import "bytes"

// This file implements cloud-platform credential validators for AWS access
// key IDs, AWS secret access keys, GCP API keys, and
// Azure storage account keys. Each function follows the same contract as
// the seed validators in validators.go: pure, panic-free functions of
// window that report a window-relative half-open span to redact.

// --- AWS access key ID ------------------------------------------------

// awsKeyIDBodyLen is the length of the RFC-4648 upper-base32 body that
// follows an AWS access key ID trigger (AKIA/ASIA/ABIA/ACCA), giving a
// 20-byte key ID overall (4-byte trigger + 16-byte body) as AWS documents.
const awsKeyIDBodyLen = 16

// awsKeyIDExampleSuffix is the tail AWS uses to mark its own documentation
// placeholder key IDs, e.g. "AKIAIOSFODNN7EXAMPLE". A real key ID's body
// never ends this way.
var awsKeyIDExampleSuffix = []byte("EXAMPLE")

// isBase32Upper reports whether c belongs to the RFC-4648 upper base32
// alphabet (A-Z, 2-7) that AWS uses for the body of an access key ID.
func isBase32Upper(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= '2' && c <= '7'
}

// isUpperOrDigit reports whether c is an ASCII uppercase letter or digit.
// AWS access key ID boundaries are broken only by this narrower set, not
// full alphanumeric: AWS never emits lowercase characters in this token, so
// a lowercase letter touching the trigger or body is not a continuation.
func isUpperOrDigit(c byte) bool {
	return c >= 'A' && c <= 'Z' || isDigit(c)
}

// AWSAccessKeyID confirms the AWS access key ID shape: one of the
// AKIA/ASIA/ABIA/ACCA triggers followed by exactly 16 RFC-4648 upper-base32
// characters, bounded on both sides by a byte that is not an uppercase
// letter or digit (or the edge of window). It rejects AWS's own
// documentation placeholder ("AKIAIOSFODNN7EXAMPLE") and, more generally,
// any key whose 16-character body ends with "EXAMPLE", which real access
// key IDs never do.
func AWSAccessKeyID(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if trigStart > 0 && isUpperOrDigit(window[trigStart-1]) {
		return 0, 0, false
	}

	bodyEnd := trigEnd + awsKeyIDBodyLen
	if bodyEnd > len(window) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	for _, c := range body {
		if !isBase32Upper(c) {
			return 0, 0, false
		}
	}
	if bodyEnd < len(window) && isUpperOrDigit(window[bodyEnd]) {
		return 0, 0, false
	}
	if bytes.HasSuffix(body, awsKeyIDExampleSuffix) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// --- AWS secret access key ---------------------------------------------

// awsSecretValueLen is the fixed length of an AWS secret access key value.
const awsSecretValueLen = 40

// awsDocsExampleSecret is the placeholder secret access key used throughout
// AWS's own documentation. It has the right shape (40 characters from the
// right alphabet) but is not a real secret, so it must never be reported as
// a match.
var awsDocsExampleSecret = []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

// isAWSSecretChar reports whether c belongs to the base64-ish alphabet AWS
// uses for secret access keys: [A-Za-z0-9/+=].
func isAWSSecretChar(c byte) bool {
	return isAlnum(c) || c == '/' || c == '+' || c == '='
}

// skipSpaces returns the offset of the first byte at or after pos that is
// not an ASCII space, never indexing out of range.
func skipSpaces(window []byte, pos int) int {
	for pos < len(window) && window[pos] == ' ' {
		pos++
	}
	return pos
}

// AWSSecretAccessKey confirms the shape of a value assigned to an
// aws_secret_access_key key (the trigger is matched case-insensitively, so
// this also fires on AWS_SECRET_ACCESS_KEY): optional spaces, a '=' or ':'
// separator, optional spaces, an optional opening quote, exactly 40
// characters of [A-Za-z0-9/+=], a matching closing quote if one was opened,
// and a boundary. Only the 40-character value is reported as the
// redaction span — the key name itself is never touched. It rejects an
// all-identical value and the well-known AWS documentation placeholder
// secret.
func AWSSecretAccessKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	pos := skipSpaces(window, trigEnd)
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
	valEnd := valStart + awsSecretValueLen
	if valEnd > len(window) {
		return 0, 0, false
	}
	value := window[valStart:valEnd]
	for _, c := range value {
		if !isAWSSecretChar(c) {
			return 0, 0, false
		}
	}

	after := valEnd
	if quote != 0 {
		if after >= len(window) || window[after] != quote {
			return 0, 0, false
		}
	} else if after < len(window) && isAWSSecretChar(window[after]) {
		return 0, 0, false
	}

	if allSame(value) {
		return 0, 0, false
	}
	if bytes.Equal(value, awsDocsExampleSecret) {
		return 0, 0, false
	}
	return valStart, valEnd, true
}

// --- GCP API key ---------------------------------------------------------

// gcpKeyBodyLen is the length of the body that follows a GCP API key's
// "AIza" trigger.
const gcpKeyBodyLen = 35

// isGCPKeyChar reports whether c belongs to the alphabet Google uses for
// the body of an API key: [0-9A-Za-z_-].
func isGCPKeyChar(c byte) bool {
	return isAlnum(c) || c == '_' || c == '-'
}

// GCPAPIKey confirms the GCP API key shape: trigger "AIza" followed by
// exactly 35 characters of [0-9A-Za-z_-], bounded on both sides by a byte
// outside that alphabet (or the edge of window). It rejects an
// all-identical body.
func GCPAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	if trigStart > 0 && isGCPKeyChar(window[trigStart-1]) {
		return 0, 0, false
	}

	bodyEnd := trigEnd + gcpKeyBodyLen
	if bodyEnd > len(window) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	for _, c := range body {
		if !isGCPKeyChar(c) {
			return 0, 0, false
		}
	}
	if bodyEnd < len(window) && isGCPKeyChar(window[bodyEnd]) {
		return 0, 0, false
	}
	if allSame(body) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// --- Azure storage account key -------------------------------------------

// azureBodyMin and azureBodyMax bound the length of the unpadded base64 run
// that precedes the "==" padding of a standard 64-byte Azure storage
// account key (86 characters for a 64-byte key, with a couple of
// characters of slack tolerated).
const (
	azureBodyMin = 86
	azureBodyMax = 88
)

// isAzureBase64Char reports whether c belongs to the unpadded base64
// alphabet [A-Za-z0-9/+].
func isAzureBase64Char(c byte) bool {
	return isAlnum(c) || c == '/' || c == '+'
}

// AzureStorageAccountKey confirms the shape of the value following an
// "AccountKey=" trigger (matched case-insensitively): 86-88 characters of
// [A-Za-z0-9/+] followed by the literal "==" padding of a standard 64-byte
// base64-encoded blob, bounded by a byte that cannot extend the base64 run
// or its padding (a ';' commonly follows in an Azure connection string,
// which already satisfies this boundary). If the base64 run reaches the
// end of window before the "==" padding can be confirmed, the match is
// rejected outright rather than guessing at what a truncated window might
// have contained.
func AzureStorageAccountKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	valStart := trigEnd
	pos := valStart
	for pos < len(window) && isAzureBase64Char(window[pos]) {
		pos++
	}
	bodyLen := pos - valStart
	if bodyLen < azureBodyMin || bodyLen > azureBodyMax {
		return 0, 0, false
	}
	if pos+2 > len(window) {
		return 0, 0, false
	}
	if window[pos] != '=' || window[pos+1] != '=' {
		return 0, 0, false
	}
	valEnd := pos + 2

	if valEnd < len(window) {
		if c := window[valEnd]; isAzureBase64Char(c) || c == '=' {
			return 0, 0, false
		}
	}
	return valStart, valEnd, true
}
