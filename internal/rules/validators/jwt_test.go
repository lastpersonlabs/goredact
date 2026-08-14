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
