package validators

import "testing"

// validatorCase is the shared table-row shape used by every ai.go
// validator's table-driven test below.
type validatorCase struct {
	name      string
	window    string
	trigStart int
	trigEnd   int
	wantOK    bool
	wantStart int
	wantEnd   int
}

func runValidatorCases(t *testing.T, fn validateFunc, cases []validatorCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := fn([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

// validateFunc (the shared local type from sourcecontrol_test.go) mirrors
// rules.ValidateFunc's signature so this test file doesn't need to import
// the rules package (which would be a cyclic dependency: rules already
// imports validators).

// aiRunNeverPanics brute-forces every (trigStart, trigEnd) pair for every
// window in windows, including windows truncated shorter than a full
// token, and fails if fn panics on any of them.
func aiRunNeverPanics(t *testing.T, name string, fn validateFunc, windows []string) {
	t.Helper()
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("%s(%q, %d, %d) panicked: %v", name, w, trigStart, trigEnd, r)
						}
					}()
					fn([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func repeat(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// alnum90 etc. are fixed, non-repeating alphanumeric bodies used to build
// realistic-length synthetic keys across the tests below. They are
// entirely synthetic (not real credentials of any kind).
const (
	anthBody90 = "L6VtNHDzbvOYIs52KThe1DBzYMxIsTnjxqnzKJgS1niDgzJKhy20RHoBqBbuVcPjhcUAwu89LeznSyn2bpa26sQIrf"
	proj40a    = "BVNMKlvU9FzBvWdqOPDZtJVcBIS5TvkvuzSLy8as"
	proj40b    = "Lq83zMskErFlHpuT9KMBRkPgrihZPskJwst1ctDX"
	proj60     = "4zROgBOLNt0ZP9sqaEZXj8WJxMSWeuquxqsQX6zBjK1bJpnvzDHlclD7U6Ro"
	legFirst20 = "EanD1OEkeGb8WP88Jk9M"
	legLast20  = "RFjmzE8XAAl7o8IzENyX"
	hf34       = "nW2OPJ0rGsD6y4OUtEXQxmAa3BItWMoP6J"
	groq52     = "wJbCoeH86zjKgop71T4uviLZ6QRKh2kwaIp2lYCV9MiujTbzw3MA"
	infix      = "T3BlbkFJ"
)

func TestAnthropicAPIKey(t *testing.T) {
	match := "sk-ant-api03-" + anthBody90 + "AA"
	cases := []validatorCase{
		{
			name:      "match at window start",
			window:    match,
			trigStart: 0,
			trigEnd:   7,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   len(match),
		},
		{
			name:      "match with surrounding context",
			window:    "Authorization: Bearer " + match + "\n",
			trigStart: 22,
			trigEnd:   29,
			wantOK:    true,
			wantStart: 22,
			wantEnd:   22 + len(match),
		},
		{
			name:      "too short body rejected",
			window:    "sk-ant-api03-short",
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
		{
			name:      "window truncated shorter than min body",
			window:    "sk-ant-abc",
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window, zero bytes follow",
			window:    "sk-ant-",
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
		{
			name:      "placeholder ellipsis body too short",
			window:    "sk-ant-xxxxxxxx…",
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
		{
			name:      "placeholder long x-run rejected despite valid length",
			window:    "sk-ant-api03-" + repeat('x', 90),
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    "sk-ant-" + repeat('A', 40),
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
		{
			name:      "prose collision preceded by alnum rejected",
			window:    "risk-ant-eater-" + anthBody90,
			trigStart: 2, // "sk-ant-" starts inside "risk-ant-"
			trigEnd:   9,
			wantOK:    false,
		},
		{
			name:      "non-alnum boundary accepted",
			window:    match + ".",
			trigStart: 0,
			trigEnd:   7,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   len(match),
		},
		{
			// match's body is 98 bytes, comfortably under the 130 max, so
			// appending one more alphanumeric byte just extends a still-
			// valid body (this is a *range*, not an exact length like
			// GitHubPAT's 36). A boundary violation only surfaces once the
			// maximal run is pushed past the upper bound entirely.
			name:      "body run exceeding 130-byte max rejected",
			window:    "sk-ant-" + anthBody90 + legFirst20 + legLast20 + "a", // 131 non-placeholder bytes
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
	}
	runValidatorCases(t, AnthropicAPIKey, cases)
}

func TestAnthropicAPIKeyNeverPanics(t *testing.T) {
	aiRunNeverPanics(t, "AnthropicAPIKey", AnthropicAPIKey, []string{
		"", "s", "sk", "sk-", "sk-a", "sk-ant-", "sk-ant-a", "sk-ant-" + repeat('a', 200), "\x00\x00\x00\x00\x00",
	})
}

func TestOpenAIProjectKey(t *testing.T) {
	withInfix := proj40a + infix + proj40b // 88 bytes, contains infix
	noInfix48 := proj60                    // 60 bytes, no infix, >=48

	cases := []validatorCase{
		{
			name:      "sk-proj- with infix confirmed",
			window:    "sk-proj-" + withInfix,
			trigStart: 0,
			trigEnd:   8,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   8 + len(withInfix),
		},
		{
			name:      "sk-svcacct- without infix but long enough confirmed",
			window:    "sk-svcacct-" + noInfix48,
			trigStart: 0,
			trigEnd:   11,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   11 + len(noInfix48),
		},
		{
			name:      "sk-admin- without infix but long enough confirmed",
			window:    "sk-admin-" + noInfix48,
			trigStart: 0,
			trigEnd:   9,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   9 + len(noInfix48),
		},
		{
			name:      "without infix below 48 rejected",
			window:    "sk-proj-" + proj60[:47],
			trigStart: 0,
			trigEnd:   8,
			wantOK:    false,
		},
		{
			name:      "below absolute 40 floor rejected even with context",
			window:    "sk-proj-short",
			trigStart: 0,
			trigEnd:   8,
			wantOK:    false,
		},
		{
			name:      "window truncated shorter than floor",
			window:    "sk-proj-abc",
			trigStart: 0,
			trigEnd:   8,
			wantOK:    false,
		},
		{
			name:      "placeholder all-same without infix rejected",
			window:    "sk-admin-" + repeat('x', 54),
			trigStart: 0,
			trigEnd:   9,
			wantOK:    false,
		},
		{
			name:      "prose collision preceded by alnum rejected",
			window:    "risk-proj-ection-" + withInfix,
			trigStart: 2,
			trigEnd:   10,
			wantOK:    false,
		},
		{
			name:      "run exceeding 200 max rejected",
			window:    "sk-proj-" + repeat('a', 201),
			trigStart: 0,
			trigEnd:   8,
			wantOK:    false,
		},
	}
	runValidatorCases(t, OpenAIProjectKey, cases)
}

func TestOpenAIProjectKeyNeverPanics(t *testing.T) {
	aiRunNeverPanics(t, "OpenAIProjectKey", OpenAIProjectKey, []string{
		"", "s", "sk-", "sk-proj-", "sk-proj-a", "sk-svcacct-", "sk-admin-", "sk-proj-" + repeat('a', 250), "\x00\x00\x00\x00",
	})
}

func TestOpenAILegacyKey(t *testing.T) {
	match := legFirst20 + infix + legLast20 // 48 bytes total

	cases := []validatorCase{
		{
			name:      "canonical 48-byte shape confirmed",
			window:    "sk-" + match,
			trigStart: 0,
			trigEnd:   3,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   3 + len(match),
		},
		{
			name:      "with surrounding context confirmed",
			window:    "OPENAI_API_KEY=sk-" + match + "\n",
			trigStart: 15,
			trigEnd:   18,
			wantOK:    true,
			wantStart: 15,
			wantEnd:   18 + len(match),
		},
		{
			name:      "too short rejected",
			window:    "sk-abcdEFGH12",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "48 bytes but missing mandatory infix rejected",
			window:    "sk-" + legFirst20 + legLast20 + legFirst20[:8],
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "window truncated shorter than 48 bytes",
			window:    "sk-" + legFirst20 + infix,
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window",
			window:    "sk-",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "overlap exclusion: sk-ant- not confirmed by legacy rule",
			window:    "sk-ant-api03-" + anthBody90 + "AA",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "overlap exclusion: sk-proj- not confirmed by legacy rule",
			window:    "sk-proj-" + proj40a + infix + proj40b,
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "overlap exclusion: sk-svcacct- not confirmed by legacy rule",
			window:    "sk-svcacct-" + proj60,
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "overlap exclusion: sk-admin- not confirmed by legacy rule",
			window:    "sk-admin-" + proj60,
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "prose collision preceded by alnum rejected",
			window:    "risk-taking " + match,
			trigStart: 2,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "preceding hyphen rejected (extended boundary)",
			window:    "x-sk-" + match,
			trigStart: 2,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "trailing alnum boundary violation rejected",
			window:    "sk-" + match + "9",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "non-alnum boundary accepted",
			window:    "sk-" + match + ".",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   3 + len(match),
		},
		{
			name:      "all-identical first segment rejected",
			window:    "sk-" + repeat('a', 20) + infix + legLast20,
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "all-identical last segment rejected",
			window:    "sk-" + legFirst20 + infix + repeat('a', 20),
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
	}
	runValidatorCases(t, OpenAILegacyKey, cases)
}

func TestOpenAILegacyKeyNeverPanics(t *testing.T) {
	aiRunNeverPanics(t, "OpenAILegacyKey", OpenAILegacyKey, []string{
		"", "s", "sk", "sk-", "sk-a", "sk-ant-", "sk-proj-", "sk-" + repeat('a', 47), "sk-" + repeat('a', 48), "\x00\x00\x00\x00",
	})
}

func TestHuggingFaceToken(t *testing.T) {
	match := "hf_" + hf34

	cases := []validatorCase{
		{
			name:      "match at window start",
			window:    match,
			trigStart: 0,
			trigEnd:   3,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   len(match),
		},
		{
			name:      "match with surrounding context",
			window:    "Authorization: Bearer " + match + "\n",
			trigStart: 22,
			trigEnd:   25,
			wantOK:    true,
			wantStart: 22,
			wantEnd:   22 + len(match),
		},
		{
			name:      "too short rejected",
			window:    "hf_short",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "identifier collision hf_hub_download rejected",
			window:    "from transformers import hf_hub_download",
			trigStart: 25,
			trigEnd:   28,
			wantOK:    false,
		},
		{
			name:      "window truncated shorter than token",
			window:    "hf_abc",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window",
			window:    "hf_",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    "hf_" + repeat('X', 34),
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "hyphen inside body truncates run and rejects",
			window:    "hf_ab-cdefghijklmnopqrstuvwxyz01234",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "trailing alnum boundary violation rejected",
			window:    match + "9",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "non-alnum boundary accepted",
			window:    match + ".",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   len(match),
		},
	}
	runValidatorCases(t, HuggingFaceToken, cases)
}

func TestHuggingFaceTokenNeverPanics(t *testing.T) {
	aiRunNeverPanics(t, "HuggingFaceToken", HuggingFaceToken, []string{
		"", "h", "hf_", "hf_a", "hf_hub_download", "hf_" + repeat('a', 34), "\x00\x00\x00\x00",
	})
}

func TestGroqAPIKey(t *testing.T) {
	match := "gsk_" + groq52

	cases := []validatorCase{
		{
			name:      "match at window start",
			window:    match,
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   len(match),
		},
		{
			name:      "match with surrounding context",
			window:    "Authorization: Bearer " + match + "\n",
			trigStart: 22,
			trigEnd:   26,
			wantOK:    true,
			wantStart: 22,
			wantEnd:   22 + len(match),
		},
		{
			name:      "too short rejected",
			window:    "gsk_short",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "window truncated shorter than token",
			window:    "gsk_abc",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window",
			window:    "gsk_",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    "gsk_" + repeat('a', 52),
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "hyphen inside body truncates run and rejects",
			window:    "gsk_" + groq52[:20] + "-" + groq52[20:],
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "run exceeds max length and rejects",
			window:    match + "Z",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "non-alnum boundary accepted",
			window:    match + ".",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   len(match),
		},
	}
	runValidatorCases(t, GroqAPIKey, cases)
}

func TestGroqAPIKeyNeverPanics(t *testing.T) {
	aiRunNeverPanics(t, "GroqAPIKey", GroqAPIKey, []string{
		"", "g", "gsk_", "gsk_a", "gsk_" + repeat('a', 52), "gsk_" + repeat('a', 60), "\x00\x00\x00\x00",
	})
}
