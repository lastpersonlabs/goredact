package validators

import "testing"

// findTrigger locates lit (case-insensitively) in window and returns its
// span, failing the test if it's not present exactly once at an
// unambiguous location for the test's purposes. Tests that need a
// specific occurrence among repeats pass an explicit trigStart/trigEnd
// instead of using this helper.
func findTrigger(t *testing.T, window, lit string) (start, end int) {
	t.Helper()
	lower := func(s string) string {
		b := []byte(s)
		for i, c := range b {
			if c >= 'A' && c <= 'Z' {
				b[i] = c - 'A' + 'a'
			}
		}
		return string(b)
	}
	idx := indexString(lower(window), lower(lit))
	if idx < 0 {
		t.Fatalf("trigger %q not found in window %q", lit, window)
	}
	return idx, idx + len(lit)
}

func indexString(haystack, needle string) int {
	if len(needle) == 0 {
		return 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestGenericAPIKeyAssignment(t *testing.T) {
	cases := []struct {
		name    string
		window  string
		trigger string
		wantOK  bool
		wantVal string
	}{
		{
			name:    "shell export unquoted",
			window:  "export API_KEY=sk_live_9fQ2vR7wL4mN8pX1sT6bF3jH0cD5yUaZ9k",
			trigger: "API_KEY",
			wantOK:  true,
			wantVal: "sk_live_9fQ2vR7wL4mN8pX1sT6bF3jH0cD5yUaZ9k",
		},
		{
			name:    "YAML double-quoted",
			window:  `api_key: "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU"`,
			trigger: "api_key",
			wantOK:  true,
			wantVal: "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU",
		},
		{
			name:    "JSON quoted with trailing brace",
			window:  `{"access_token": "Xk9mP2vQ7Rt4Ws8LbN3jF6hZ1cYdA0eB5g"}`,
			trigger: "access_token",
			wantOK:  true,
			wantVal: "Xk9mP2vQ7Rt4Ws8LbN3jF6hZ1cYdA0eB5g",
		},
		{
			name:    "fat-arrow separator",
			window:  `client_secret => "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU"`,
			trigger: "client_secret",
			wantOK:  true,
			wantVal: "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU",
		},
		{
			name:    "single-quoted",
			window:  `secret_key = 'aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU'`,
			trigger: "secret_key",
			wantOK:  true,
			wantVal: "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU",
		},
		{
			name:    "trailing comma stops unquoted value",
			window:  `api_key=aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU,other=1`,
			trigger: "api_key",
			wantOK:  true,
			wantVal: "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU",
		},
		{
			name:    "placeholder value rejected",
			window:  `api_key = "your-api-key-here-1234567890"`,
			trigger: "api_key",
			wantOK:  false,
		},
		{
			name:    "uuid value rejected",
			window:  `client_secret: "550e8400-e29b-41d4-a716-446655440000"`,
			trigger: "client_secret",
			wantOK:  false,
		},
		{
			name:    "low-entropy word value rejected",
			window:  `secret_key = "hello_world_this_is_config"`,
			trigger: "secret_key",
			wantOK:  false,
		},
		{
			name:    "no separator following trigger",
			window:  `api_key_rotation_period = 30`,
			trigger: "api_key",
			wantOK:  false,
		},
		{
			name:    "too short value",
			window:  `api_key = "short1"`,
			trigger: "api_key",
			wantOK:  false,
		},
		{name: "Python type annotation", window: `api_key: Optional[str]`, trigger: "api_key", wantOK: false},
		{name: "Rust type annotation", window: `api_key: Option<String>`, trigger: "api_key", wantOK: false},
		{name: "environment lookup", window: `api_key=os.environ.get("GROQ_API_KEY")`, trigger: "api_key", wantOK: false},
		{name: "JavaScript environment reference", window: `api_key=process.env.GROQ_API_KEY`, trigger: "api_key", wantOK: false},
		{name: "shell variable reference", window: `api_key=${ANTHROPIC_API_KEY:-fallback}`, trigger: "api_key", wantOK: false},
		{name: "secret manager reference", window: `api_key=op://RecountableDev/Anthropic/key`, trigger: "api_key", wantOK: false},
		{name: "documentation URL", window: `api-key: https://developers.example.invalid/docs/api-keys`, trigger: "api-key", wantOK: false},
		{name: "member reference", window: `api_key=cfg.typesense_api_key`, trigger: "api_key", wantOK: false},
		{name: "escaped logical newline", window: `api_key=dev_resend_api_key\\nnext_field`, trigger: "api_key", wantOK: false},
		{name: "development placeholder", window: `client_secret=dev-client-secret`, trigger: "client_secret", wantOK: false},
		{name: "configuration member", window: `api_key=config.search.exaApiKey`, trigger: "api_key", wantOK: false},
		{name: "environment member", window: `secret_key=env.STRIPE_SECRET_KEY`, trigger: "secret_key", wantOK: false},
		{name: "vault descriptor", window: `api_key=vault=ExampleVault`, trigger: "api_key", wantOK: false},
		{name: "HTML encoded source", window: `api_key=pk_live_ckPnmJJZTFKgKGv6RihxsV8g&amp`, trigger: "api_key", wantOK: false},
		{name: "regex expression", window: `api_key=|^CODEX|^CHATGPT`, trigger: "api_key", wantOK: false},
		{name: "base64 padding remains valid", window: `api_key=QWxhZGRpbjpvcGVuIHNlc2FtZQ==`, trigger: "api_key", wantOK: true, wantVal: "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			window := []byte(tc.window)
			ts, te := findTrigger(t, tc.window, tc.trigger)
			start, end, ok := GenericAPIKeyAssignment(window, ts, te)
			if ok != tc.wantOK {
				t.Fatalf("GenericAPIKeyAssignment(%q) ok = %v, want %v", tc.window, ok, tc.wantOK)
			}
			if ok && string(window[start:end]) != tc.wantVal {
				t.Errorf("GenericAPIKeyAssignment(%q) value = %q, want %q", tc.window, window[start:end], tc.wantVal)
			}
		})
	}
}

// TestGenericAPIKeyAssignmentBoundary confirms the identifier-collision
// boundary rule directly: "api_key" as a suffix of a longer identifier
// ("capi_key") must not fire, but a preceding '_' or '-' (a common word
// separator) must not block it either.
func TestGenericAPIKeyAssignmentBoundary(t *testing.T) {
	cases := []struct {
		name   string
		window string
		wantOK bool
	}{
		{
			name:   "preceded by underscore fires",
			window: `x_api_key = "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU"`,
			wantOK: true,
		},
		{
			name:   "preceded by hyphen fires",
			window: `x-api_key = "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU"`,
			wantOK: true,
		},
		{
			name:   "suffix of longer identifier does not fire",
			window: `capi_key = "randomsecretvalueXk9mP2vQ7Rt4Ws8"`,
			wantOK: false,
		},
		{
			name:   "at start of window fires",
			window: `api_key = "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU"`,
			wantOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			window := []byte(tc.window)
			ts, te := findTrigger(t, tc.window, "api_key")
			_, _, ok := GenericAPIKeyAssignment(window, ts, te)
			if ok != tc.wantOK {
				t.Fatalf("GenericAPIKeyAssignment(%q) ok = %v, want %v", tc.window, ok, tc.wantOK)
			}
		})
	}
}

func TestGenericPasswordAssignment(t *testing.T) {
	cases := []struct {
		name    string
		window  string
		trigger string
		wantOK  bool
		wantVal string
	}{
		{
			name:    "shell export unquoted",
			window:  "export PASSWORD=Xk9mP2vQ7Rt4Ws8Lb",
			trigger: "PASSWORD",
			wantOK:  true,
			wantVal: "Xk9mP2vQ7Rt4Ws8Lb",
		},
		{
			name:    "YAML double-quoted",
			window:  `password: "Zt7Qp2Xk9mLwR4vN8"`,
			trigger: "password",
			wantOK:  true,
			wantVal: "Zt7Qp2Xk9mLwR4vN8",
		},
		{
			name:    "JSON quoted short key pwd",
			window:  `{"pwd": "aZ9kQ2vR7wL4mN8pX1sT6bF3"}`,
			trigger: "pwd",
			wantOK:  true,
			wantVal: "aZ9kQ2vR7wL4mN8pX1sT6bF3",
		},
		{
			name:    "placeholder changeme rejected",
			window:  `password = "changeme"`,
			trigger: "password",
			wantOK:  false,
		},
		{
			name:    "uuid value rejected",
			window:  `passwd: "550e8400-e29b-41d4-a716-446655440000"`,
			trigger: "passwd",
			wantOK:  false,
		},
		{
			name:    "pure dictionary word rejected",
			window:  `password = "configuration"`,
			trigger: "password",
			wantOK:  false,
		},
		{
			name:    "bare pwd shell command",
			window:  `pwd`,
			trigger: "pwd",
			wantOK:  false,
		},
		{
			name:    "pwd command with shell prompt",
			window:  `$ pwd`,
			trigger: "pwd",
			wantOK:  false,
		},
		{
			name:    "nsswitch-style passwd line",
			window:  `passwd: files systemd`,
			trigger: "passwd",
			wantOK:  false,
		},
		{name: "template reference", window: `password=${STORAGE_SECRET_ACCESS_KEY:-fallback}`, trigger: "password", wantOK: false},
		{name: "function call", window: `password=String(data.get("password"))`, trigger: "password", wantOK: false},
		{name: "secret manager reference", window: `password=op://ExampleVault/Postgres/password`, trigger: "password", wantOK: false},
		{name: "escaped logical newline", window: `password=secret123\\nnext`, trigger: "password", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			window := []byte(tc.window)
			ts, te := findTrigger(t, tc.window, tc.trigger)
			start, end, ok := GenericPasswordAssignment(window, ts, te)
			if ok != tc.wantOK {
				t.Fatalf("GenericPasswordAssignment(%q) ok = %v, want %v", tc.window, ok, tc.wantOK)
			}
			if ok && string(window[start:end]) != tc.wantVal {
				t.Errorf("GenericPasswordAssignment(%q) value = %q, want %q", tc.window, window[start:end], tc.wantVal)
			}
		})
	}
}

func TestGenericBearerLikeTokenAssignment(t *testing.T) {
	cases := []struct {
		name    string
		window  string
		wantOK  bool
		wantVal string
	}{
		{
			name:    "shell export unquoted",
			window:  "export TOKEN=aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yUaZ9k",
			wantOK:  true,
			wantVal: "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yUaZ9k",
		},
		{
			name:    "YAML double-quoted",
			window:  `token: "Xk9mP2vQ7Rt4Ws8LbN3jF6hZ1cYdA0eB5gC7h"`,
			wantOK:  true,
			wantVal: "Xk9mP2vQ7Rt4Ws8LbN3jF6hZ1cYdA0eB5gC7h",
		},
		{
			name:   "code call is not a token",
			window: `token = csv.next()`,
			wantOK: false,
		},
		{
			name:   "angle bracket placeholder",
			window: `token: <YOUR_TOKEN>`,
			wantOK: false,
		},
		{
			name:   "your- placeholder value",
			window: `token = "your-token-here-1234567890abcdef"`,
			wantOK: false,
		},
		{
			name:   "uuid value rejected",
			window: `token: "550e8400-e29b-41d4-a716-446655440000"`,
			wantOK: false,
		},
		{
			name:   "word-like value rejected",
			window: `token = "helloworldconfigurationvalue"`,
			wantOK: false,
		},
		{
			name:   "too short even if random-looking",
			window: `token = "Xk9mP2vQ7Rt"`,
			wantOK: false,
		},
		{name: "SQL expression", window: `token = sqlc.arg(claim_token)`, wantOK: false},
		{name: "template reference", window: `token=${GIT_REPOSITORY_INTERNAL_TOKEN:-fallback}`, wantOK: false},
		{name: "secret manager reference", window: `token=op://ExampleVault/Cloudflare/token`, wantOK: false},
		{name: "member reference", window: `token=EXCLUDED.refresh_token`, wantOK: false},
		{name: "function call", window: `token=bearerToken(request.headers.get("authorization"))`, wantOK: false},
		{name: "Terraform reference", window: `token=var.cloudflare_api_token`, wantOK: false},
		{name: "constant identifier", window: `token=BASE_WATCHER_INTERNAL_API_TOKEN`, wantOK: false},
		{name: "blockchain address", window: `token=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			window := []byte(tc.window)
			ts, te := findTrigger(t, tc.window, "token")
			start, end, ok := GenericBearerLikeTokenAssignment(window, ts, te)
			if ok != tc.wantOK {
				t.Fatalf("GenericBearerLikeTokenAssignment(%q) ok = %v, want %v", tc.window, ok, tc.wantOK)
			}
			if ok && string(window[start:end]) != tc.wantVal {
				t.Errorf("GenericBearerLikeTokenAssignment(%q) value = %q, want %q", tc.window, window[start:end], tc.wantVal)
			}
		})
	}
}

// TestGenericValidatorsNeverPanic runs every generic validator across a
// grid of truncation points on a handful of representative windows,
// confirming none of them ever panics regardless of where trigStart/
// trigEnd/window boundaries fall — the same defensive contract as the
// seed validators in validators_test.go.
func TestGenericValidatorsNeverPanic(t *testing.T) {
	windows := []string{
		"",
		"api_key",
		"api_key=",
		"api_key=\"",
		"api_key=\"abc",
		`export API_KEY=sk_live_9fQ2vR7wL4mN8pX1sT6bF3jH0cD5yUaZ9k`,
		`password: "Zt7Qp2Xk9mLwR4vN8"`,
		`token: "Xk9mP2vQ7Rt4Ws8LbN3jF6hZ1cYdA0eB5gC7h"`,
		"\x00\x00\x00\x00",
	}
	fns := map[string]func([]byte, int, int) (int, int, bool){
		"GenericAPIKeyAssignment":          GenericAPIKeyAssignment,
		"GenericPasswordAssignment":        GenericPasswordAssignment,
		"GenericBearerLikeTokenAssignment": GenericBearerLikeTokenAssignment,
	}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				for name, fn := range fns {
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
}

func TestIsTriggerBoundaryOK(t *testing.T) {
	if !isTriggerBoundaryOK([]byte("api_key"), 0) {
		t.Error("trigStart at 0 should always be OK")
	}
	if !isTriggerBoundaryOK([]byte("_api_key"), 1) {
		t.Error("preceded by underscore should be OK")
	}
	if !isTriggerBoundaryOK([]byte("-api_key"), 1) {
		t.Error("preceded by hyphen should be OK")
	}
	if isTriggerBoundaryOK([]byte("capi_key"), 1) {
		t.Error("preceded by alnum should not be OK")
	}
}

func TestParseAssignmentValueSeparators(t *testing.T) {
	cases := []struct {
		window  string
		wantOK  bool
		wantVal string
	}{
		{"= value1234567890", true, "value1234567890"},
		{": value1234567890", true, "value1234567890"},
		{"=> value1234567890", true, "value1234567890"},
		{"value1234567890", false, ""},
		{"   ", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.window, func(t *testing.T) {
			start, end, ok := parseAssignmentValue([]byte(tc.window), 0)
			if ok != tc.wantOK {
				t.Fatalf("parseAssignmentValue(%q) ok = %v, want %v", tc.window, ok, tc.wantOK)
			}
			if ok && tc.window[start:end] != tc.wantVal {
				t.Errorf("parseAssignmentValue(%q) value = %q, want %q", tc.window, tc.window[start:end], tc.wantVal)
			}
		})
	}
}
