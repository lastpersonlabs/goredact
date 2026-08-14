package validators

import "testing"

// paymentsCase is the common table-row shape shared by every table-driven test
// in this file: a window, the trigger span within it, and the expected
// outcome (with wantEnd only meaningful when wantOK is true — start is
// always trigStart on success for every validator in this file).
type paymentsCase struct {
	name      string
	window    string
	trigStart int
	trigEnd   int
	wantOK    bool
	wantEnd   int
}

func runPaymentsCases(t *testing.T, fn func(window []byte, trigStart, trigEnd int) (int, int, bool), cases []paymentsCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := fn([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.trigStart || end != tc.wantEnd) {
				t.Errorf("(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.trigStart, tc.wantEnd)
			}
		})
	}
}

// paymentsAssertNeverPanics exhaustively calls fn over every (trigStart, trigEnd) pair
// within 0..len(w) for each w in windows, confirming it never panics
// regardless of how nonsensical or truncated the inputs are relative to
// what fn expects to find there.
func paymentsAssertNeverPanics(t *testing.T, fn func(window []byte, trigStart, trigEnd int) (int, int, bool), windows []string) {
	t.Helper()
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					fn([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

// ---------------------------------------------------------------------
// stripe-secret-key / StripeSecretKey
// ---------------------------------------------------------------------

func TestStripeSecretKey(t *testing.T) {
	const body32 = "oHBvRPOIvGrv5iFlbCBFNOgmBjMtpsia" // 32 mixed alnum chars
	const body24 = "OclRz3AwzKsbVRJN9wVGFYGW"         // 24 chars: min bound
	const body99 = "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3vW5xY7zA9bC1dE3fG5hJ7kL9mN1pQ3rS5tU7"

	cases := []paymentsCase{
		{name: "sk_live_ min length body accepted", window: "sk_live_" + body24, trigStart: 0, trigEnd: 8, wantOK: true, wantEnd: 8 + len(body24)},
		{name: "sk_test_ mid length body accepted (test-mode still redacted)", window: "sk_test_" + body32, trigStart: 0, trigEnd: 8, wantOK: true, wantEnd: 8 + len(body32)},
		{name: "rk_live_ trigger accepted", window: "rk_live_" + body32, trigStart: 0, trigEnd: 8, wantOK: true, wantEnd: 8 + len(body32)},
		{name: "rk_test_ trigger accepted", window: "rk_test_" + body32, trigStart: 0, trigEnd: 8, wantOK: true, wantEnd: 8 + len(body32)},
		{name: "max length body accepted", window: "sk_live_" + body99, trigStart: 0, trigEnd: 8, wantOK: true, wantEnd: 8 + len(body99)},
		{name: "one below min length rejected", window: "sk_live_" + body24[:23], trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "one above max length rejected (no valid boundary)", window: "sk_live_" + body99 + "Z", trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "all-identical body rejected as placeholder", window: "sk_live_" + string(makeN('X', 30)), trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "hyphen breaks alnum run, resulting run too short", window: "sk_live_" + body24[:10] + "-" + body24[10:], trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "non-alnum trailing boundary accepted", window: "sk_live_" + body32 + ".", trigStart: 0, trigEnd: 8, wantOK: true, wantEnd: 8 + len(body32)},
		{name: "trigger at very end of window, zero body bytes", window: "sk_live_", trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "window truncated shorter than min body", window: "sk_live_short", trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "trailing context preserved on match", window: "x=sk_live_" + body32 + "\nnext", trigStart: 2, trigEnd: 10, wantOK: true, wantEnd: 10 + len(body32)},
	}
	runPaymentsCases(t, StripeSecretKey, cases)
}

func TestStripeSecretKeyNeverPanics(t *testing.T) {
	paymentsAssertNeverPanics(t, StripeSecretKey, []string{"", "s", "sk_live_", "sk_live_a", "\x00\x00\x00\x00"})
}

// ---------------------------------------------------------------------
// stripe-webhook-secret / StripeWebhookSecret
// ---------------------------------------------------------------------

func TestStripeWebhookSecret(t *testing.T) {
	const body32 = "7YFjS1on43XkMtECqOxSF2O3GYRdo1XK" // 32 chars: min bound
	const body64 = "pEmoKiuPKdYR7osjOrU1xxDO0CzUZREN68k4tUNpfZ46pdJQIPvjiQvlb5lZXOIg"

	cases := []paymentsCase{
		{name: "min length body accepted", window: "whsec_" + body32, trigStart: 0, trigEnd: 6, wantOK: true, wantEnd: 6 + len(body32)},
		{name: "max length body accepted", window: "whsec_" + body64, trigStart: 0, trigEnd: 6, wantOK: true, wantEnd: 6 + len(body64)},
		{name: "one below min length rejected", window: "whsec_" + body32[:31], trigStart: 0, trigEnd: 6, wantOK: false},
		{name: "one above max length rejected", window: "whsec_" + body64 + "Z", trigStart: 0, trigEnd: 6, wantOK: false},
		{name: "all-identical body rejected as placeholder", window: "whsec_" + string(makeN('Z', 40)), trigStart: 0, trigEnd: 6, wantOK: false},
		{name: "underscore breaks alnum run, resulting run too short", window: "whsec_" + body32[:19] + "_" + body32[19:], trigStart: 0, trigEnd: 6, wantOK: false},
		{name: "non-alnum trailing boundary accepted", window: "whsec_" + body32 + ",", trigStart: 0, trigEnd: 6, wantOK: true, wantEnd: 6 + len(body32)},
		{name: "trailing alnum run exceeds max length, rejected", window: "whsec_" + body64 + "9", trigStart: 0, trigEnd: 6, wantOK: false},
		{name: "trigger at very end of window", window: "whsec_", trigStart: 0, trigEnd: 6, wantOK: false},
	}
	runPaymentsCases(t, StripeWebhookSecret, cases)
}

func TestStripeWebhookSecretNeverPanics(t *testing.T) {
	paymentsAssertNeverPanics(t, StripeWebhookSecret, []string{"", "w", "whsec_", "whsec_a", "\x00\x00\x00\x00"})
}

// ---------------------------------------------------------------------
// slack-user-token / SlackUserToken
// ---------------------------------------------------------------------

func TestSlackUserToken(t *testing.T) {
	const d11a = "80184514627"
	const d12a = "048281489325"
	const final30 = "wKi9x7h6AmUfBH7X41zTPDP4k8FFuf" // 30 alnum chars, two-group final segment

	const d10b = "1822782489"
	const d11b = "63834657871"
	const d12b = "331509839301"
	const final24 = "1721a278f64f7fd633dbdde1" // 24 alnum chars, three-group final segment

	twoGroup := "xoxa-" + d11a + "-" + d12a + "-" + final30
	threeGroup := "xoxp-" + d10b + "-" + d11b + "-" + d12b + "-" + final24

	cases := []paymentsCase{
		{name: "two-group shape accepted (xoxa-)", window: twoGroup, trigStart: 0, trigEnd: 5, wantOK: true, wantEnd: len(twoGroup)},
		{name: "three-group shape accepted (xoxp-)", window: threeGroup, trigStart: 0, trigEnd: 5, wantOK: true, wantEnd: len(threeGroup)},
		{name: "xoxr- trigger accepted", window: "xoxr-" + d11a + "-" + d12a + "-" + final30, trigStart: 0, trigEnd: 5, wantOK: true, wantEnd: len("xoxr-" + d11a + "-" + d12a + "-" + final30)},
		{name: "xoxs- trigger accepted", window: "xoxs-" + d11a + "-" + d12a + "-" + final30, trigStart: 0, trigEnd: 5, wantOK: true, wantEnd: len("xoxs-" + d11a + "-" + d12a + "-" + final30)},
		{name: "digit groups too short rejected", window: "xoxa-123-456-abcdefgh0123456789abcd", trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "digit group too long rejected", window: "xoxa-" + "123456789012345" + "-" + d12a + "-" + final30, trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "missing separator dash rejected", window: "xoxa-" + d11a + d12a + "-" + final30, trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "final segment too short rejected", window: "xoxa-" + d11a + "-" + d12a + "-short", trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "final segment all identical rejected as placeholder", window: "xoxa-" + d11a + "-" + d12a + "-" + string(makeN('a', 28)), trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "trailing alnum run exceeds max length, rejected", window: twoGroup + "ZZZZZ", trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "non-alnum boundary accepted", window: twoGroup + ".", trigStart: 0, trigEnd: 5, wantOK: true, wantEnd: len(twoGroup)},
		{name: "trigger at very end of window", window: "xoxa-", trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "empty window", window: "", trigStart: 0, trigEnd: 0, wantOK: false},
	}
	runPaymentsCases(t, SlackUserToken, cases)
}

func TestSlackUserTokenNeverPanics(t *testing.T) {
	paymentsAssertNeverPanics(t, SlackUserToken, []string{"", "x", "xoxa-", "xoxa-1", "xoxa-1-2-", "xoxa-1-2-3-", "\x00\x00\x00\x00\x00"})
}

// ---------------------------------------------------------------------
// slack-app-token / SlackAppToken
// ---------------------------------------------------------------------

func TestSlackAppToken(t *testing.T) {
	const groupB = "GPMM82I1LR3"
	const groupC = "3178108013267"
	const groupD = "f6c15c0c8e9df469611a11f5125227c3712da86a78c49ea20e32684b27b95e90" // 64 lowercase hex

	full := "1-" + groupB + "-" + groupC + "-" + groupD // total run length after "xapp-": 92 chars
	maxRun := full + string(makeN('c', 8))              // padded to exactly 100 chars: the max

	cases := []paymentsCase{
		{name: "full documented shape accepted", window: "xapp-" + full, trigStart: 0, trigEnd: 5, wantOK: true, wantEnd: 5 + len(full)},
		{name: "max length run accepted", window: "xapp-" + maxRun, trigStart: 0, trigEnd: 5, wantOK: true, wantEnd: 5 + len(maxRun)},
		{name: "too short overall rejected", window: "xapp-1-ABC-123", trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "fewer than 3 dashes rejected despite valid length", window: "xapp-" + string(makeN('A', 20)) + "-" + string(makeN('B', 22)), trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "all-dash run rejected as placeholder", window: "xapp-" + string(makeN('-', 45)), trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "non-charset byte ends run early, too short", window: "xapp-1-ABC-123-456 " + groupD, trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "trailing alnum run exceeds max length, rejected", window: "xapp-" + maxRun + "d", trigStart: 0, trigEnd: 5, wantOK: false},
		{name: "non-alnum boundary accepted", window: "xapp-" + full + " end", trigStart: 0, trigEnd: 5, wantOK: true, wantEnd: 5 + len(full)},
		{name: "trigger at very end of window", window: "xapp-", trigStart: 0, trigEnd: 5, wantOK: false},
	}
	runPaymentsCases(t, SlackAppToken, cases)
}

func TestSlackAppTokenNeverPanics(t *testing.T) {
	paymentsAssertNeverPanics(t, SlackAppToken, []string{"", "x", "xapp-", "xapp-1", "xapp----", "\x00\x00\x00\x00"})
}

// ---------------------------------------------------------------------
// sendgrid-api-key / SendGridAPIKey
// ---------------------------------------------------------------------

func TestSendGridAPIKey(t *testing.T) {
	const seg1 = "OhWhEN3so3OxYgF3AZu3Iq"                      // 22 urlSafe chars
	const seg2 = "oPmn0pzlQY1wWmzAmka3p744b8VKkqLencZSDFf8J61" // 43 urlSafe chars
	const seg1Dash = "Yx-zfSAN2cW7GfP6R7o425"                  // 22 chars including a hyphen
	const seg2Underscore = "U85hfj_ej4JkeiqoKRTdxTbI10q71Ha1xCw9Atmx1c_"

	match := "SG." + seg1 + "." + seg2

	cases := []paymentsCase{
		{name: "match at window start", window: match, trigStart: 0, trigEnd: 3, wantOK: true, wantEnd: len(match)},
		{name: "hyphen/underscore chars in segments accepted", window: "SG." + seg1Dash + "." + seg2Underscore, trigStart: 0, trigEnd: 3, wantOK: true, wantEnd: len("SG." + seg1Dash + "." + seg2Underscore)},
		{name: "preceded by identifier byte rejected (MSG. collision)", window: "M" + match, trigStart: 1, trigEnd: 4, wantOK: false},
		{name: "preceded by digit rejected", window: "9" + match, trigStart: 1, trigEnd: 4, wantOK: false},
		{name: "preceded by non-identifier byte accepted", window: "=" + match, trigStart: 1, trigEnd: 4, wantOK: true, wantEnd: 1 + len(match)},
		{name: "at start of window (no preceding byte) accepted", window: match, trigStart: 0, trigEnd: 3, wantOK: true, wantEnd: len(match)},
		{name: "seg1 one char short (dot arrives early) rejected", window: "SG." + seg1[:21] + "." + seg2, trigStart: 0, trigEnd: 3, wantOK: false},
		{name: "seg1 one char too long rejected", window: "SG." + seg1 + "X." + seg2, trigStart: 0, trigEnd: 3, wantOK: false},
		{name: "missing dot separator rejected", window: "SG." + seg1 + seg2, trigStart: 0, trigEnd: 3, wantOK: false},
		{name: "space inside seg2 rejected", window: "SG." + seg1 + "." + seg2[:20] + " " + seg2[21:], trigStart: 0, trigEnd: 3, wantOK: false},
		{name: "all-identical seg2 rejected as placeholder", window: "SG." + seg1 + "." + string(makeN('a', 43)), trigStart: 0, trigEnd: 3, wantOK: false},
		{name: "urlSafe trailing boundary violation rejected", window: match + "z", trigStart: 0, trigEnd: 3, wantOK: false},
		{name: "non-urlSafe trailing boundary accepted", window: match + " ", trigStart: 0, trigEnd: 3, wantOK: true, wantEnd: len(match)},
		{name: "trigger at very end of window", window: "SG.", trigStart: 0, trigEnd: 3, wantOK: false},
	}
	runPaymentsCases(t, SendGridAPIKey, cases)
}

func TestSendGridAPIKeyNeverPanics(t *testing.T) {
	paymentsAssertNeverPanics(t, SendGridAPIKey, []string{"", "S", "SG.", "SG.a", "SG.a.", "MSG.", "\x00\x00\x00\x00"})
}

// ---------------------------------------------------------------------
// twilio-api-key-sid / TwilioAPIKeySID
// ---------------------------------------------------------------------

func TestTwilioAPIKeySID(t *testing.T) {
	const hex32 = "3931bdb2a0df3dbe4d58fed8a728e7ec" // 32 lowercase hex chars

	match := "SK" + hex32

	cases := []paymentsCase{
		{name: "match at window start", window: match, trigStart: 0, trigEnd: 2, wantOK: true, wantEnd: len(match)},
		{name: "preceded by identifier byte rejected (TASK collision)", window: "TA" + match, trigStart: 2, trigEnd: 4, wantOK: false},
		{name: "preceded by identifier byte rejected (DESK collision)", window: "DE" + match, trigStart: 2, trigEnd: 4, wantOK: false},
		{name: "preceded by underscore rejected", window: "_" + match, trigStart: 1, trigEnd: 3, wantOK: false},
		{name: "preceded by non-identifier byte accepted", window: " " + match, trigStart: 1, trigEnd: 3, wantOK: true, wantEnd: 1 + len(match)},
		{name: "at start of window (no preceding byte) accepted", window: match, trigStart: 0, trigEnd: 2, wantOK: true, wantEnd: len(match)},
		{name: "uppercase hex rejected (must be lowercase)", window: "SK" + "3931BDB2A0DF3DBE4D58FED8A728E7EC", trigStart: 0, trigEnd: 2, wantOK: false},
		{name: "too short rejected", window: "SK" + hex32[:30], trigStart: 0, trigEnd: 2, wantOK: false},
		{name: "non-hex char rejected", window: "SK" + hex32[:31] + "g", trigStart: 0, trigEnd: 2, wantOK: false},
		{name: "all-identical body rejected as placeholder", window: "SK" + string(makeN('a', 32)), trigStart: 0, trigEnd: 2, wantOK: false},
		{name: "trailing alnum boundary violation rejected", window: match + "9", trigStart: 0, trigEnd: 2, wantOK: false},
		{name: "non-alnum trailing boundary accepted", window: match + ")", trigStart: 0, trigEnd: 2, wantOK: true, wantEnd: len(match)},
		{name: "trigger at very end of window", window: "SK", trigStart: 0, trigEnd: 2, wantOK: false},
	}
	runPaymentsCases(t, TwilioAPIKeySID, cases)
}

func TestTwilioAPIKeySIDNeverPanics(t *testing.T) {
	paymentsAssertNeverPanics(t, TwilioAPIKeySID, []string{"", "S", "SK", "SKa", "TASK", "DESK", "\x00\x00\x00\x00"})
}

// ---------------------------------------------------------------------
// linear-api-key / LinearAPIKey
// ---------------------------------------------------------------------

func TestLinearAPIKey(t *testing.T) {
	const body40 = "FeWaVUqG2KVasfSq8Z0wjCdFUQUHxZ3g0Aq3idaD" // 40 chars: min bound
	const body60 = "MhXnwfocwDNRjI7Sc4sfHBomzPtKTjAjaFO16Hd8Hp1Jf7tSgtRa1eePdjJY"

	cases := []paymentsCase{
		{name: "min length body accepted", window: "lin_api_" + body40, trigStart: 0, trigEnd: 8, wantOK: true, wantEnd: 8 + len(body40)},
		{name: "max length body accepted", window: "lin_api_" + body60, trigStart: 0, trigEnd: 8, wantOK: true, wantEnd: 8 + len(body60)},
		{name: "one below min length rejected", window: "lin_api_" + body40[:len(body40)-10], trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "one above max length rejected", window: "lin_api_" + body60 + "Z", trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "hyphen breaks alnum run, resulting run too short", window: "lin_api_" + body40[:20] + "-" + body40[20:], trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "all-identical body rejected as placeholder", window: "lin_api_" + string(makeN('Q', 45)), trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "non-alnum trailing boundary accepted", window: "lin_api_" + body40 + "!", trigStart: 0, trigEnd: 8, wantOK: true, wantEnd: 8 + len(body40)},
		{name: "trailing alnum run exceeds max length, rejected", window: "lin_api_" + body60 + "z", trigStart: 0, trigEnd: 8, wantOK: false},
		{name: "trigger at very end of window", window: "lin_api_", trigStart: 0, trigEnd: 8, wantOK: false},
	}
	runPaymentsCases(t, LinearAPIKey, cases)
}

func TestLinearAPIKeyNeverPanics(t *testing.T) {
	paymentsAssertNeverPanics(t, LinearAPIKey, []string{"", "l", "lin_api_", "lin_api_a", "\x00\x00\x00\x00"})
}

// ---------------------------------------------------------------------
// notion-internal-token / NotionInternalToken
// ---------------------------------------------------------------------

func TestNotionInternalToken(t *testing.T) {
	const secretBody = "JcieWVjwiYd7U3MsPkYO2xaCUvet6zYYqy0pJf9CIg9" // exactly 43 chars
	const ntnBody46 = "LFn3YnrPf6lJOdoQdQqA5zd5SriKEc8WlTo9bsQd2TMY2e"
	const ntnBody60 = "GPYkWkSsSB1qZRAk3rxvD6mvf155SxzOmzWOoMnQrwuxqr1IoG5opCTycClX"

	secretMatch := "secret_" + secretBody
	ntnMatch46 := "ntn_" + ntnBody46
	ntnMatch60 := "ntn_" + ntnBody60

	cases := []paymentsCase{
		{name: "secret_ exact 43-char body accepted", window: secretMatch, trigStart: 0, trigEnd: 7, wantOK: true, wantEnd: len(secretMatch)},
		{name: "ntn_ min length body accepted", window: ntnMatch46, trigStart: 0, trigEnd: 4, wantOK: true, wantEnd: len(ntnMatch46)},
		{name: "ntn_ max length body accepted", window: ntnMatch60, trigStart: 0, trigEnd: 4, wantOK: true, wantEnd: len(ntnMatch60)},
		{name: "secret_ preceded by identifier byte rejected (client_secret_ collision)", window: "client_" + secretMatch, trigStart: 7, trigEnd: 14, wantOK: false},
		{name: "secret_ preceded by non-identifier byte accepted", window: "=" + secretMatch, trigStart: 1, trigEnd: 8, wantOK: true, wantEnd: 1 + len(secretMatch)},
		{name: "secret_ at start of window (no preceding byte) accepted", window: secretMatch, trigStart: 0, trigEnd: 7, wantOK: true, wantEnd: len(secretMatch)},
		{name: "secret_ one char short rejected", window: "secret_" + secretBody[:42], trigStart: 0, trigEnd: 7, wantOK: false},
		{name: "secret_ one char too long rejected", window: "secret_" + secretBody + "Z", trigStart: 0, trigEnd: 7, wantOK: false},
		{name: "secret_ all-identical body rejected as placeholder", window: "secret_" + string(makeN('a', 43)), trigStart: 0, trigEnd: 7, wantOK: false},
		{name: "ntn_ one below min length rejected", window: "ntn_" + ntnBody46[:45], trigStart: 0, trigEnd: 4, wantOK: false},
		{name: "ntn_ one above max length rejected", window: "ntn_" + ntnBody60 + "Z", trigStart: 0, trigEnd: 4, wantOK: false},
		{name: "ntn_ all-identical body rejected as placeholder", window: "ntn_" + string(makeN('b', 50)), trigStart: 0, trigEnd: 4, wantOK: false},
		{name: "ntn_ not subject to preceding-byte rule", window: "client_" + ntnMatch46, trigStart: 7, trigEnd: 11, wantOK: true, wantEnd: 7 + len(ntnMatch46)},
		{name: "unrecognized trigger length rejected safely", window: "xx" + secretBody, trigStart: 0, trigEnd: 2, wantOK: false},
		{name: "trigger at very end of window (secret_)", window: "secret_", trigStart: 0, trigEnd: 7, wantOK: false},
		{name: "trigger at very end of window (ntn_)", window: "ntn_", trigStart: 0, trigEnd: 4, wantOK: false},
	}
	runPaymentsCases(t, NotionInternalToken, cases)
}

func TestNotionInternalTokenNeverPanics(t *testing.T) {
	paymentsAssertNeverPanics(t, NotionInternalToken, []string{"", "s", "secret_", "secret_a", "ntn_", "ntn_a", "client_secret_", "\x00\x00\x00\x00\x00\x00\x00"})
}

// Note: makeN(c byte, n int) []byte is already declared in
// validators_test.go (same package); this file reuses it rather than
// redeclaring it.
