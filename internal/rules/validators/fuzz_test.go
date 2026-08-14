package validators

import (
	"bytes"
	"testing"
)

type fuzzValidator struct {
	name    string
	trigger string
	fn      func([]byte, int, int) (int, int, bool)
}

// fuzzValidators is deliberately explicit. A new production validator must be
// added here, making the fuzz target an auditable inventory rather than a
// reflection-based smoke test that can silently miss new code.
var fuzzValidators = []fuzzValidator{
	{"AnthropicAPIKey", "sk-ant-", AnthropicAPIKey},
	{"OpenAIProjectKey", "sk-proj-", OpenAIProjectKey},
	{"OpenAILegacyKey", "sk-", OpenAILegacyKey},
	{"HuggingFaceToken", "hf_", HuggingFaceToken},
	{"GroqAPIKey", "gsk_", GroqAPIKey},
	{"AWSAccessKeyID", "AKIA", AWSAccessKeyID},
	{"AWSSecretAccessKey", "aws_secret_access_key", AWSSecretAccessKey},
	{"GCPAPIKey", "AIza", GCPAPIKey},
	{"AzureStorageAccountKey", "AccountKey", AzureStorageAccountKey},
	{"AuthorizationHeader", "Authorization:", AuthorizationHeader},
	{"CookieSessionToken", "Cookie:", CookieSessionToken},
	{"URLCredentials", "://", URLCredentials},
	{"CommandLinePasswordFlag", "--password", CommandLinePasswordFlag},
	{"GenericAPIKeyAssignment", "api_key", GenericAPIKeyAssignment},
	{"GenericPasswordAssignment", "password", GenericPasswordAssignment},
	{"GenericBearerLikeTokenAssignment", "access_token", GenericBearerLikeTokenAssignment},
	{"StripeSecretKey", "sk_live_", StripeSecretKey},
	{"StripeWebhookSecret", "whsec_", StripeWebhookSecret},
	{"SlackBotToken", "xoxb-", SlackBotToken},
	{"SlackUserToken", "xoxp-", SlackUserToken},
	{"SlackAppToken", "xapp-", SlackAppToken},
	{"SendGridAPIKey", "SG.", SendGridAPIKey},
	{"TwilioAPIKeySID", "SK", TwilioAPIKeySID},
	{"LinearAPIKey", "lin_api_", LinearAPIKey},
	{"NotionInternalToken", "ntn_", NotionInternalToken},
	{"PEMPrivateKey", "-----BEGIN ", PEMPrivateKey},
	{"PuTTYPrivateKey", "PuTTY-User-Key-File-", PuTTYPrivateKey},
	{"GitHubPAT", "ghp_", GitHubPAT},
	{"GitHubOAuthToken", "gho_", GitHubOAuthToken},
	{"GitHubAppToken", "ghs_", GitHubAppToken},
	{"GitHubRefreshToken", "ghr_", GitHubRefreshToken},
	{"GitHubFineGrainedPAT", "github_pat_", GitHubFineGrainedPAT},
	{"GitLabPAT", "glpat-", GitLabPAT},
	{"GitLabRunnerToken", "GR1348941", GitLabRunnerToken},
	{"GitLabDeployToken", "gldt-", GitLabDeployToken},
	{"NpmAccessToken", "npm_", NpmAccessToken},
	{"PyPIAPIToken", "pypi-", PyPIAPIToken},
	{"DockerHubPAT", "dckr_pat_", DockerHubPAT},
}

func checkValidatorResult(t *testing.T, v fuzzValidator, window []byte, ts, te int) {
	t.Helper()
	start, end, ok := v.fn(window, ts, te)
	if !ok {
		return
	}
	if start < 0 || start >= end || end > len(window) {
		t.Fatalf("%s returned invalid confirmed span [%d,%d) for window length %d", v.name, start, end, len(window))
	}
}

// FuzzAllValidators feeds arbitrary bytes (including invalid UTF-8) around a
// real trigger through every validator. It also exercises truncation at both
// sides of the trigger. Besides panic freedom, every confirmed result must be
// a non-empty, in-window half-open span: the streaming engine relies on that
// invariant before merging and writing spans.
func FuzzAllValidators(f *testing.F) {
	f.Add([]byte(nil), uint8(0), uint16(0))
	f.Add([]byte("\x00\xff\\\"\r\n"), uint8(1), uint16(3))
	f.Add(bytes.Repeat([]byte("A"), 4096), uint8(2), uint16(2048))
	f.Add([]byte(`user:p%40ss@host/path?x=1`), uint8(3), uint16(5))
	f.Add([]byte(`\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END PRIVATE KEY-----`), uint8(4), uint16(0))

	f.Fuzz(func(t *testing.T, data []byte, selector uint8, split uint16) {
		const maxData = 16 << 10
		if len(data) > maxData {
			data = data[:maxData]
		}
		v := fuzzValidators[int(selector)%len(fuzzValidators)]
		cut := 0
		if len(data) != 0 {
			cut = int(split) % (len(data) + 1)
		}
		window := make([]byte, 0, len(data)+len(v.trigger))
		window = append(window, data[:cut]...)
		ts := len(window)
		window = append(window, v.trigger...)
		te := len(window)
		window = append(window, data[cut:]...)

		checkValidatorResult(t, v, window, ts, te)
		// EOF/chunk truncation immediately after the trigger is a distinct
		// parser state for lookahead-heavy contextual and private-key rules.
		checkValidatorResult(t, v, window[:te], ts, te)
		// A trigger at offset zero catches accidental negative lookbehind.
		zero := append([]byte(v.trigger), data...)
		checkValidatorResult(t, v, zero, 0, len(v.trigger))
	})
}

func TestAllValidatorsHugeAndArbitraryBytes(t *testing.T) {
	// This is deterministic CI coverage for sizes fuzz minimisation tends to
	// discard. Validators receive bounded windows in production, but must stay
	// allocation-safe and linear when called directly with a large value.
	tail := bytes.Repeat([]byte{0xff, 0x00, 'A', '\\', '"', '\n'}, 1<<16)
	for _, v := range fuzzValidators {
		t.Run(v.name, func(t *testing.T) {
			window := append([]byte(v.trigger), tail...)
			checkValidatorResult(t, v, window, 0, len(v.trigger))
		})
	}
}
