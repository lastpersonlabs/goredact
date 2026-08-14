package goredact

import (
	"strings"
	"testing"
)

// Synthetic credential values for the ENG-100 contextual rules. Entirely
// fabricated; shaped to pass the entropy/placeholder gates.
const (
	ctxBearerVal  = "mZ7xW4pL9sN3tYbF6hR0cD5gU1aEkJ8v" // Authorization: Bearer value
	ctxCookieVal  = "aK9mQ2vR7wL4mN8pX1sTbF3j"         // sessionid cookie value
	ctxURLPass    = "wZ8kQ3vR7pL4mN2x"                 // DSN userinfo password
	ctxJSONBearer = "pQ2vR7wL4mN8xT6bF9jH0cD5yU1aEkJ8vZ3"
)

// contextualMixedLog builds a realistic mixed log — an HTTP request dump,
// connection-string config lines, documentation lines, and a JSONL record
// embedding an escaped header — with the given strings in the four
// credential positions. Building input and expected output from the same
// function keeps the byte-for-byte assertions honest: the only difference
// between them is the four substitutions.
func contextualMixedLog(bearer, cookie, urlPass, jsonBearer string) string {
	return "GET /api/v1/orders HTTP/1.1\n" +
		"Host: api.example.com\n" +
		"Authorization: Bearer " + bearer + "\n" +
		"Cookie: theme=dark; sessionid=" + cookie + "; lang=en\n" +
		"User-Agent: curl/8.5.0\n" +
		"\n" +
		"db=postgres://svc_user:" + urlPass + "@db.internal:5432/app\n" +
		"cache=redis://cache.internal:6379/0\n" +
		"docs: Authorization: Bearer <token>\n" +
		"status https://status.example.com/ ok\n" +
		`{"evt":"req","hdr":"\"authorization: bearer ` + jsonBearer + `\""}` + "\n"
}

// TestRedactContextualMixedLog runs the full engine over the mixed log in
// both ProfileFast and ProfileBalanced and asserts exact output:
//   - Authorization values (plain and JSON-escaped) redacted in both
//     profiles; header name and scheme preserved.
//   - The URL password redacted in both profiles with the URL structure
//     (scheme, user, host, port, path) preserved byte for byte around it.
//   - The cookie rule is profile-gated: inactive in fast (the Cookie line
//     passes through untouched), active in balanced.
//   - No over-redaction anywhere: every benign line is asserted unchanged
//     via whole-output equality.
func TestRedactContextualMixedLog(t *testing.T) {
	in := contextualMixedLog(ctxBearerVal, ctxCookieVal, ctxURLPass, ctxJSONBearer)
	m := DefaultMarker

	t.Run("fast", func(t *testing.T) {
		e := mustEngine(t, Config{Profile: ProfileFast})
		out, stats := redactAll(t, e, strings.NewReader(in))

		want := contextualMixedLog(m, ctxCookieVal, m, m)
		if out != want {
			t.Fatalf("fast output:\n%q\nwant:\n%q", out, want)
		}
		if !strings.Contains(out, "db=postgres://svc_user:"+m+"@db.internal:5432/app\n") {
			t.Errorf("URL structure not preserved around marker:\n%q", out)
		}
		if !strings.Contains(out, "Cookie: theme=dark; sessionid="+ctxCookieVal+"; lang=en\n") {
			t.Errorf("cookie rule fired in fast profile:\n%q", out)
		}
		wantByRule := map[string]int{
			"authorization-bearer": 2,
			"url-credentials":      1,
		}
		assertByRule(t, stats.ByRule, wantByRule)
	})

	t.Run("balanced", func(t *testing.T) {
		e := mustEngine(t, Config{Profile: ProfileBalanced})
		out, stats := redactAll(t, e, strings.NewReader(in))

		want := contextualMixedLog(m, m, m, m)
		if out != want {
			t.Fatalf("balanced output:\n%q\nwant:\n%q", out, want)
		}
		if !strings.Contains(out, "Cookie: theme=dark; sessionid="+m+"; lang=en\n") {
			t.Errorf("cookie value not redacted (or cookie structure damaged):\n%q", out)
		}
		wantByRule := map[string]int{
			"authorization-bearer": 2,
			"url-credentials":      1,
			"cookie-session-token": 1,
		}
		assertByRule(t, stats.ByRule, wantByRule)
	})
}

func assertByRule(t *testing.T, got, want map[string]int) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("ByRule = %v, want %v", got, want)
		return
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("ByRule[%q] = %d, want %d (full: %v)", id, got[id], n, got)
		}
	}
}
