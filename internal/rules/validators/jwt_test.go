package validators

import "testing"

// Synthetic JWS segments: base64url of synthetic JSON, plus a random-looking
// signature. Never derived from real credentials.
const (
	jwtHeader  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"                           // {"alg":"HS256","typ":"JWT"}
	jwtPayload = "eyJzdWIiOiJ1c2VyLTQ4MjEiLCJzY29wZSI6InRyYW5zY3JpcHRzOnJlYWQifQ" // synthetic claims
	jwtSig     = "q4TnV7bXk2LwZ9pR0sYhF6dJ1aG5uEiO8cM3rTvQ6wN"                    // 43 random-looking base64url bytes
)

var jwtFull = jwtHeader + "." + jwtPayload + "." + jwtSig

func TestJWT(t *testing.T) {
	cases := []contextualCase{
		{
			name:    "bare token at start of window",
			window:  jwtFull,
			trig:    "eyJ",
			wantOK:  true,
			wantVal: jwtFull,
		},
		{
			name:    "token in prose, terminated by space",
			window:  "exchange returned " + jwtFull + " for the session",
			trig:    "eyJ",
			wantOK:  true,
			wantVal: jwtFull,
		},
		{
			name:    "assignment context keeps a preceding equals sign legal",
			window:  "export OIDC_ID_TOKEN=" + jwtFull,
			trig:    "eyJ",
			wantOK:  true,
			wantVal: jwtFull,
		},
		{
			name:    "JSON string value terminates at the closing quote",
			window:  `{"id_token":"` + jwtFull + `"}`,
			trig:    "eyJ",
			wantOK:  true,
			wantVal: jwtFull,
		},
		{
			name:    "escaped JSON terminates at the backslash",
			window:  `{"stdout":"got ` + jwtFull + `\n"}`,
			trig:    "eyJ",
			wantOK:  true,
			wantVal: jwtFull,
		},
		{
			name:    "base64 padding is consumed into the span",
			window:  jwtFull + "== trailing",
			trig:    "eyJ",
			wantOK:  true,
			wantVal: jwtFull + "==",
		},
		{
			name:   "preceding base64url byte rejects (mid-blob eyJ)",
			window: "QmFzZTY0eyJibG9i" + jwtFull,
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "preceding dot rejects (payload firing of an outer JWT)",
			window: "sig." + jwtPayload + "." + jwtSig,
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "header segment alone is not a JWT",
			window: jwtHeader + " decoded to a JSON header",
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "two segments without a signature reject",
			window: jwtHeader + "." + jwtPayload,
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "payload segment must start with ey",
			window: jwtHeader + ".pZ8kQ2vR7wL4mN0pX1sTqRs7.hB3jF6hZ1cYdA0eBqG",
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "short payload segment rejects",
			window: jwtHeader + ".eyJhIjoxfQ." + jwtSig,
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "short signature rejects",
			window: jwtHeader + "." + jwtPayload + ".c2ln",
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "placeholder signature rejects",
			window: jwtHeader + "." + jwtPayload + ".xxxxxxxxxxxxxxxx",
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "alphanumeric byte after padding rejects",
			window: jwtFull + "=0",
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "third padding byte rejects",
			window: jwtFull + "===",
			trig:   "eyJ",
			wantOK: false,
		},
	}
	runContextualCases(t, JWT, cases)
}

// TestJWTWindowEdge pins the truncation policy: a signature run ending
// exactly at the window edge is accepted (end of input, or a token longer
// than the lookahead — redacting the buffered prefix protects more than
// rejecting the whole token), while a window ending before the signature
// exists rejects.
func TestJWTWindowEdge(t *testing.T) {
	full := []byte(jwtFull)
	ts, te := findTrigger(t, jwtFull, "eyJ")

	start, end, ok := JWT(full, ts, te)
	if !ok || start != 0 || end != len(full) {
		t.Fatalf("full window: got (%d, %d, %v), want (0, %d, true)", start, end, ok, len(full))
	}

	// Truncate mid-signature: still accepted, span ends at the window edge.
	cut := len(jwtFull) - 20
	start, end, ok = JWT(full[:cut], ts, te)
	if !ok || start != 0 || end != cut {
		t.Fatalf("mid-signature window: got (%d, %d, %v), want (0, %d, true)", start, end, ok, cut)
	}

	// Truncate mid-payload: no signature separator, rejected.
	if _, _, ok = JWT(full[:len(jwtHeader)+10], ts, te); ok {
		t.Fatal("mid-payload window: got ok, want reject")
	}
}

// Synthetic Supabase-shaped JWS segments. The payloads decode (base64url)
// to synthetic JSON claim sets; never derived from a real credential.
const (
	supabasePayloadServiceRole       = "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMTUzNTY4MDB9"             // {"iss":"supabase","ref":"abcdefghijklmnop","role":"service_role","iat":1700000000,"exp":2015356800}
	supabasePayloadServiceRoleSpaced = "eyJyb2xlIjogInNlcnZpY2Vfcm9sZSIsICJpc3MiOiAic3VwYWJhc2UiLCAicmVmIjogImFiY2RlZmdoaWprbG1ub3AiLCAiaWF0IjogMTcwMDAwMDAwMCwgImV4cCI6IDIwMTUzNTY4MDB9" // {"role": "service_role", "iss": "supabase", ...} (spaced JSON)
	supabasePayloadAnon              = "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDE1MzU2ODAwfQ"                       // {"iss":"supabase",...,"role":"anon",...}
	supabasePayloadNoRole            = "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MjAxNTM1NjgwMH0"                                          // {"iss":"supabase",...} (no role claim at all)
	supabaseSig1                     = "TsKdOf3JR-kSPIbMXpSE2IlyTs8tIAGHgmy-qA5m_Xc"
	supabaseSig2                     = "EbrK-izzHh_fuSf8Ubf5ItUGm0ZkL0-HuL6cVkAnoqs"
)

var (
	supabaseServiceRoleToken       = jwtHeader + "." + supabasePayloadServiceRole + "." + supabaseSig1
	supabaseServiceRoleTokenSpaced = jwtHeader + "." + supabasePayloadServiceRoleSpaced + "." + supabaseSig2
	supabaseAnonToken              = jwtHeader + "." + supabasePayloadAnon + "." + supabaseSig2
	supabaseNoRoleToken            = jwtHeader + "." + supabasePayloadNoRole + "." + supabaseSig1
)

func TestSupabaseServiceRoleKey(t *testing.T) {
	cases := []contextualCase{
		{
			name:    "service_role claim matches",
			window:  "SUPABASE_SERVICE_ROLE_KEY=" + supabaseServiceRoleToken,
			trig:    "eyJ",
			wantOK:  true,
			wantVal: supabaseServiceRoleToken,
		},
		{
			name:    "service_role claim matches with spaced JSON and reordered fields",
			window:  "key: " + supabaseServiceRoleTokenSpaced,
			trig:    "eyJ",
			wantOK:  true,
			wantVal: supabaseServiceRoleTokenSpaced,
		},
		{
			name:   "anon role rejected",
			window: "SUPABASE_ANON_KEY=" + supabaseAnonToken,
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "missing role claim rejected",
			window: "token=" + supabaseNoRoleToken,
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "generic bare JWT without a role claim rejected",
			window: jwtFull,
			trig:   "eyJ",
			wantOK: false,
		},
		{
			name:   "malformed non-JWT shape rejected same as JWT",
			window: jwtHeader + "." + jwtPayload,
			trig:   "eyJ",
			wantOK: false,
		},
	}
	runContextualCases(t, SupabaseServiceRoleKey, cases)
}

func TestSupabaseServiceRoleKeyNeverPanics(t *testing.T) {
	windows := []string{
		"", "eyJ", "eyJ.", "eyJ..", supabaseServiceRoleToken, supabaseServiceRoleToken[:20],
		supabaseServiceRoleToken[:len(jwtHeader)+len(supabasePayloadServiceRole)+2],
		"\x00\x00\x00\x00\x00\x00",
	}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("SupabaseServiceRoleKey(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					SupabaseServiceRoleKey([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestHasServiceRoleClaim(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    bool
	}{
		{"exact match", `{"role":"service_role","iss":"supabase"}`, true},
		{"space after colon", `{"role": "service_role"}`, true},
		{"space before colon", `{"role" :"service_role"}`, true},
		{"reordered fields", `{"iss":"supabase","role":"service_role","iat":1}`, true},
		{"anon role", `{"role":"anon"}`, false},
		{"no role field", `{"iss":"supabase"}`, false},
		{"role key as substring of another key", `{"consumer_role":"service_role"}`, false},
		{"role value merely prefixed by service_role rejected (closing quote required)", `{"role":"service_role_extra"}`, false},
		{"empty payload", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasServiceRoleClaim([]byte(tc.payload)); got != tc.want {
				t.Errorf("hasServiceRoleClaim(%q) = %v, want %v", tc.payload, got, tc.want)
			}
		})
	}
}
