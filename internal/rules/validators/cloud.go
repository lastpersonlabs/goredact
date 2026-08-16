package validators

import "bytes"

// This file implements cloud-platform and infrastructure credential
// validators: AWS access key IDs, AWS secret access keys, AWS Bedrock
// long-lived and short-lived API keys, GCP API keys, Azure storage
// account keys, Azure Service Bus/Event Hubs shared access keys, Azure
// App Configuration secrets, HashiCorp Vault service and batch tokens,
// and HCP Terraform/Terraform Enterprise API tokens. Each function
// follows the same contract as the seed validators in validators.go:
// pure, panic-free functions of window that report a window-relative
// half-open span to redact.

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
	if isPlaceholder(body) {
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
// not an ASCII space or horizontal tab, never indexing out of range.
func skipSpaces(window []byte, pos int) int {
	for pos < len(window) && (window[pos] == ' ' || window[pos] == '\t') {
		pos++
	}
	return pos
}

// AWSSecretAccessKey confirms the shape of a value assigned to an
// aws_secret_access_key key (the trigger is matched case-insensitively, so
// this also fires on AWS_SECRET_ACCESS_KEY): optional spaces/tabs, a '='
// or ':' separator (optionally preceded by a JSON-style closing quote),
// optional spaces/tabs, an optional opening quote, exactly 40 characters
// of [A-Za-z0-9/+=], a matching closing quote if one was opened, and a
// boundary. Only the 40-character value is reported as the redaction
// span — the key name itself is never touched. It rejects an
// all-identical value and the well-known AWS documentation placeholder
// secret.
func AWSSecretAccessKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	valStart, valEnd, ok := consumeAssignedValue(window, trigEnd, awsSecretValueLen, isAWSSecretChar)
	if !ok {
		return 0, 0, false
	}
	if bytes.Equal(window[valStart:valEnd], awsDocsExampleSecret) {
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
	if isPlaceholder(body) {
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
// have contained. It rejects a placeholder body, mirroring
// azureShortBase64Secret below.
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
	body := window[valStart:pos]
	valEnd := pos + 2

	if valEnd < len(window) {
		if c := window[valEnd]; isAzureBase64Char(c) || c == '=' {
			return 0, 0, false
		}
	}
	if isPlaceholder(body) {
		return 0, 0, false
	}
	return valStart, valEnd, true
}

// --- Azure Service Bus / Event Hubs shared access key, App Configuration
// secret ------------------------------------------------------------------

// azureShortSecretBodyMin and azureShortSecretBodyMax bound the length of
// the unpadded base64 run that precedes the single "=" padding character
// of a standard 32-byte (256-bit) Azure shared access key or App
// Configuration secret (43 characters for a 32-byte value, with a
// couple of characters of slack tolerated, mirroring the same slack
// AzureStorageAccountKey allows for its own, differently-sized key).
const (
	azureShortSecretBodyMin = 42
	azureShortSecretBodyMax = 44
)

// azureShortBase64Secret confirms a standard base64-encoded 256-bit
// secret immediately following trigEnd: 42-44 characters of
// [A-Za-z0-9/+] followed by the literal "=" padding of a 32-byte value,
// bounded by a byte that cannot extend the base64 run or its padding. It
// backs both AzureServiceBusSASKey and AzureAppConfigurationSecret, which
// are byte-for-byte the same shape (a base64-encoded 256-bit HMAC key)
// under two different connection-string grammars.
func azureShortBase64Secret(window []byte, trigEnd int) (start, end int, ok bool) {
	valStart := trigEnd
	pos := valStart
	for pos < len(window) && isAzureBase64Char(window[pos]) {
		pos++
	}
	bodyLen := pos - valStart
	if bodyLen < azureShortSecretBodyMin || bodyLen > azureShortSecretBodyMax {
		return 0, 0, false
	}
	if pos >= len(window) || window[pos] != '=' {
		return 0, 0, false
	}
	body := window[valStart:pos]
	valEnd := pos + 1

	if valEnd < len(window) {
		if c := window[valEnd]; isAzureBase64Char(c) || c == '=' {
			return 0, 0, false
		}
	}
	if isPlaceholder(body) {
		return 0, 0, false
	}
	return valStart, valEnd, true
}

// AzureServiceBusSASKey confirms the shape of the value following a
// "SharedAccessKey=" trigger (matched case-insensitively). Service Bus,
// Event Hubs, and Relay namespaces all share this one SAS mechanism under
// an identical "sb://...servicebus.windows.net" connection-string
// grammar — the connection string alone cannot distinguish which of the
// three issued a given key, so this rule covers all of them.
//
// https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas
// https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string
func AzureServiceBusSASKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return azureShortBase64Secret(window, trigEnd)
}

// AzureAppConfigurationSecret confirms the shape of the value following a
// "Secret=" trigger (matched case-insensitively) in an App Configuration
// connection string ("Endpoint=...;Id=...;Secret=..."). This is the
// classic 32-byte base64 key shape; a longer, unpadded variant has been
// observed for some App Configuration secrets but is not yet documented
// by Microsoft, so it is deliberately not matched here rather than
// guessed at.
//
// https://learn.microsoft.com/en-us/azure/azure-app-configuration/enable-dynamic-configuration-dotnet-core-push-refresh
func AzureAppConfigurationSecret(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return azureShortBase64Secret(window, trigEnd)
}

// --- HashiCorp Vault tokens ------------------------------------------------

// vaultServiceTokenBodyMin/Max and vaultBatchTokenBodyMin/Max bound the
// length of the token body following the "hvs."/"hvb." prefix. HashiCorp
// deliberately does not publish a formal length contract for this shape
// (it has already changed once, when Vault 1.10 introduced longer
// Server-Side Consistent Tokens) and says so explicitly in its own
// community forum. These ranges cover both the original 24-character
// base62 body HashiCorp's token-generation code still uses as a baseline
// and the longer base64url-ish SSCT body real 1.10+ deployments issue,
// with slack on both ends — the same "generous practical ceiling, not a
// documented maximum" approach already used here for PyPIAPIToken and
// DockerHubPAT (sourcecontrol.go).
const (
	vaultServiceTokenBodyMin = 20
	vaultServiceTokenBodyMax = 150
	vaultBatchTokenBodyMin   = 100
	vaultBatchTokenBodyMax   = 300
)

// VaultServiceToken confirms the HashiCorp Vault service token shape:
// trigger "hvs." followed by 20-150 characters from [A-Za-z0-9_-]. A
// Vault service token grants whatever access its policies allow, up to
// full administrative control of everything Vault manages.
//
// https://github.com/hashicorp/vault/blob/main/vault/token_store.go (TokenPrefixLength, TokenLength)
// https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml (production length range)
func VaultServiceToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return runToken(window, trigStart, trigEnd, vaultServiceTokenBodyMin, vaultServiceTokenBodyMax)
}

// VaultBatchToken confirms the HashiCorp Vault batch token shape: trigger
// "hvb." followed by 100-300 characters from [A-Za-z0-9_-]. Batch tokens
// are the same blast-radius class as service tokens (whatever their
// policies allow) but encode more state directly into the token, which is
// why their body runs longer.
//
// https://github.com/hashicorp/vault/blob/main/vault/token_store.go (TokenPrefixLength, TokenLength)
// https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml (production length range)
func VaultBatchToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return runToken(window, trigStart, trigEnd, vaultBatchTokenBodyMin, vaultBatchTokenBodyMax)
}

// --- HCP Terraform / Terraform Enterprise API token -----------------------

// terraformPrefixLen is the length of the alphanumeric segment that
// precedes the ".atlasv1." infix (a holdover from Terraform's old "Atlas"
// product name) in every HCP Terraform/Terraform Enterprise API token,
// regardless of whether it is a user, team, organization, agent, or
// audit-trail token — the token string itself does not distinguish
// between those scopes.
const terraformPrefixLen = 14

// terraformSecretMin and terraformSecretMax bound the length of the
// segment following ".atlasv1.". HashiCorp does not publish a formal
// length contract; these bounds match every token length shown across
// HCP Terraform's own user/team/organization API token documentation.
const (
	terraformSecretMin = 60
	terraformSecretMax = 70
)

// isTerraformSecretChar reports whether c belongs to the alphabet HCP
// Terraform uses for the secret segment following ".atlasv1.":
// alphanumeric plus '-', '_', and '='.
func isTerraformSecretChar(c byte) bool {
	return isAlnum(c) || c == '-' || c == '_' || c == '='
}

// TerraformCloudAPIToken confirms the HCP Terraform/Terraform Enterprise
// API token shape: a 14-character alphanumeric prefix, the literal
// trigger ".atlasv1.", and a 60-70 character secret from
// [A-Za-z0-9_=-], bounded on the left by a byte that cannot extend the
// prefix backward (or the edge of window). A token with this shape grants
// read/modify access to Terraform Cloud-managed infrastructure state,
// which routinely contains further embedded secrets (provider
// credentials, database passwords) in its resource attributes and
// outputs.
//
// https://developer.hashicorp.com/terraform/cloud-docs/api-docs/user-tokens
// https://developer.hashicorp.com/terraform/cloud-docs/api-docs/team-tokens
// https://developer.hashicorp.com/terraform/cloud-docs/api-docs/organization-tokens
func TerraformCloudAPIToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	prefixStart := trigStart - terraformPrefixLen
	if prefixStart < 0 {
		return 0, 0, false
	}
	if prefixStart > 0 && isAlnum(window[prefixStart-1]) {
		return 0, 0, false
	}
	prefix := window[prefixStart:trigStart]
	if !allAlnum(prefix) {
		return 0, 0, false
	}

	secretEnd, ok := consumeRun(window, trigEnd, terraformSecretMin, terraformSecretMax, isTerraformSecretChar)
	if !ok {
		return 0, 0, false
	}
	secret := window[trigEnd:secretEnd]
	if isPlaceholder(prefix) || isPlaceholder(secret) {
		return 0, 0, false
	}
	return prefixStart, secretEnd, true
}

// --- AWS Bedrock API keys --------------------------------------------------

// isBedrockBase64Char reports whether c belongs to the non-padding
// standard base64 alphabet [A-Za-z0-9+/] Amazon Bedrock API keys use for
// their body.
func isBedrockBase64Char(c byte) bool {
	return isAlnum(c) || c == '+' || c == '/'
}

// consumeBedrockBody consumes a run of isBedrockBase64Char bytes within
// [min, max] starting at pos, followed by up to two '=' padding bytes,
// and reports the end offset — provided the byte after any padding
// cannot itself extend the base64 run or its padding. It never indexes
// out of range.
func consumeBedrockBody(window []byte, pos, min, max int) (end int, ok bool) {
	bodyEnd, ok := consumeRun(window, pos, min, max, isBedrockBase64Char)
	if !ok {
		return 0, false
	}
	end = bodyEnd
	for pad := 0; pad < 2 && end < len(window) && window[end] == '='; pad++ {
		end++
	}
	if end < len(window) && (isBedrockBase64Char(window[end]) || window[end] == '=') {
		return 0, false
	}
	return end, true
}

// bedrockLongLivedBodyMin and bedrockLongLivedBodyMax bound the length of
// the base64 run following the rule's trigger, "ABSKQmVkcm9ja0FQSUtleS"
// ("ABSK" plus the base64 encoding of the literal "BedrockAPIKey").
// Matching this whole anchor as the trigger (rather than just "ABSK")
// makes the trigger itself close to unique, which is what lets this rule
// run at high confidence. AWS does not publish an exact body length;
// these bounds match the community-converged detection ranges
// independent tooling (gitleaks, git-secrets derivatives) uses, shifted
// down by the 18 characters the anchor already consumes beyond the bare
// "ABSK" prefix those tools trigger on.
const (
	bedrockLongLivedBodyMin = 91
	bedrockLongLivedBodyMax = 251
)

// AWSBedrockLongLivedAPIKey confirms the Amazon Bedrock long-lived API
// key shape: the fixed trigger "ABSKQmVkcm9ja0FQSUtleS", followed by
// 91-251 further characters of standard base64 and up to two '=' padding
// characters — the base64 encoding of a structured
// "BedrockAPIKey-<id>-at-<account-id>:<secret>" payload that AWS accepts
// in place of SigV4 credentials for calling Bedrock's model-invocation
// APIs.
//
// https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html
// https://github.com/awslabs/git-secrets (canonical AWS-maintained detection pattern)
func AWSBedrockLongLivedAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	bodyEnd, ok := consumeBedrockBody(window, trigEnd, bedrockLongLivedBodyMin, bedrockLongLivedBodyMax)
	if !ok {
		return 0, 0, false
	}
	if isPlaceholder(window[trigEnd:bodyEnd]) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// bedrockShortLivedBodyMin and bedrockShortLivedBodyMax bound the length
// of the base64 run following the rule's trigger,
// "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t" ("bedrock-api-key-" plus
// the base64 encoding of the literal host "bedrock.amazonaws.com" — every
// short-lived key is the base64 encoding of a SigV4-presigned URL against
// that host, so this substring is present at a fixed offset in every one
// of them; AWS's own detection tooling, git-secrets, uses this exact
// fixed string, with no wildcard body at all, as its canonical pattern).
// Unlike the long-lived key, this body's length is genuinely unbounded in
// practice: it is the base64 encoding of a full presigned-URL query
// string, which grows past a thousand characters once it embeds an STS
// session token. bedrockShortLivedBodyMax is a generous practical
// ceiling, not a documented maximum — the same convention already used
// here for PyPIAPIToken and DockerHubPAT (sourcecontrol.go).
const (
	bedrockShortLivedBodyMin = 20
	bedrockShortLivedBodyMax = 4096
)

// AWSBedrockShortLivedAPIKey confirms the Amazon Bedrock short-lived API
// key shape: the fixed trigger
// "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t", followed by 20-4096
// further characters of standard base64 and up to two '=' padding
// characters.
//
// https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html
// https://github.com/aws/aws-bedrock-token-generator-js (canonical AWS-maintained token construction)
// https://github.com/awslabs/git-secrets (canonical AWS-maintained detection pattern)
func AWSBedrockShortLivedAPIKey(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	bodyEnd, ok := consumeBedrockBody(window, trigEnd, bedrockShortLivedBodyMin, bedrockShortLivedBodyMax)
	if !ok {
		return 0, 0, false
	}
	if isPlaceholder(window[trigEnd:bodyEnd]) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}
