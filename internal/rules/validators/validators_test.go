package validators

import "testing"

func TestGitHubPAT(t *testing.T) {
	const body36 = "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLr" // 36 mixed alnum chars

	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantStart int
		wantEnd   int
	}{
		{
			name:      "match at window start",
			window:    "ghp_" + body36,
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   4 + 36,
		},
		{
			name:      "match with trailing context",
			window:    "x=ghp_" + body36 + "\nnext",
			trigStart: 2,
			trigEnd:   6,
			wantOK:    true,
			wantStart: 2,
			wantEnd:   6 + 36,
		},
		{
			name:      "match at exact window end (no trailing byte)",
			window:    "ghp_" + body36,
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   4 + 36,
		},
		{
			name:      "window truncated shorter than token",
			window:    "ghp_short",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window, zero bytes follow",
			window:    "ghp_",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    "ghp_" + string(make36('X')),
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "non-alnum inside body rejected",
			window:    "ghp_" + body36[:35] + "!",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "alnum boundary violation rejected",
			window:    "ghp_" + body36 + "A",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "non-alnum boundary accepted",
			window:    "ghp_" + body36 + ".",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   4 + 36,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := GitHubPAT([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("GitHubPAT(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("GitHubPAT(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestGitHubPATNeverPanics(t *testing.T) {
	windows := []string{"", "g", "ghp_", "ghp_a", "\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := -1; trigStart <= len(w)+1; trigStart++ {
			for trigEnd := -1; trigEnd <= len(w)+1; trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("GitHubPAT(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					if trigEnd >= trigStart && trigStart >= 0 && trigEnd <= len(w) {
						GitHubPAT([]byte(w), trigStart, trigEnd)
					}
				}()
			}
		}
	}
}

func make36(c byte) []byte {
	b := make([]byte, 36)
	for i := range b {
		b[i] = c
	}
	return b
}

func TestSlackBotToken(t *testing.T) {
	const d13a = "0265423511615"
	const d13b = "5940781618495"
	const seg30 = "KmTecQoXsf2o3gyrDO1xkxwnQrS7RP" // 30 alnum chars, not all identical

	match := "xoxb-" + d13a + "-" + d13b + "-" + seg30

	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantEnd   int
	}{
		{
			name:      "match at window start",
			window:    match,
			trigStart: 0,
			trigEnd:   5,
			wantOK:    true,
			wantEnd:   len(match),
		},
		{
			name:      "match with trailing context",
			window:    "token: " + match + " end",
			trigStart: 7,
			trigEnd:   12,
			wantOK:    true,
			wantEnd:   7 + len(match),
		},
		{
			name:      "digits too short",
			window:    "xoxb-123-456-abcdefgh",
			trigStart: 0,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "digits too long",
			window:    "xoxb-" + "123456789012345" + "-" + d13b + "-" + seg30,
			trigStart: 0,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "missing separator dash",
			window:    "xoxb-" + d13a + d13b + "-" + seg30,
			trigStart: 0,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "trailing segment too short",
			window:    "xoxb-" + d13a + "-" + d13b + "-short",
			trigStart: 0,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "trailing segment all identical rejected",
			window:    "xoxb-" + d13a + "-" + d13b + "-" + string(makeN('a', 28)),
			trigStart: 0,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			// seg30 is already 30 alphanumeric characters (within the
			// 24-34 valid range); appending 5 more pushes the maximal
			// alnum run to 35, past the max, so no valid sub-length has a
			// non-alnum boundary after it and the whole match is rejected
			// (mirrors how a bounded-quantifier regex plus a boundary
			// assertion behaves).
			name:      "trailing alnum run exceeds max length, rejected",
			window:    match + "ZZZZZ",
			trigStart: 0,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "non-alnum boundary accepted",
			window:    match + ".",
			trigStart: 0,
			trigEnd:   5,
			wantOK:    true,
			wantEnd:   len(match),
		},
		{
			name:      "trigger at very end of window",
			window:    "xoxb-",
			trigStart: 0,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "empty window",
			window:    "",
			trigStart: 0,
			trigEnd:   0,
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := SlackBotToken([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("SlackBotToken(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.trigStart || end != tc.wantEnd) {
				t.Errorf("SlackBotToken(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.trigStart, tc.wantEnd)
			}
		})
	}
}

func TestSlackBotTokenNeverPanics(t *testing.T) {
	windows := []string{"", "x", "xoxb-", "xoxb-1", "xoxb-1-2-", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("SlackBotToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					SlackBotToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func makeN(c byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return b
}

func TestHelpers(t *testing.T) {
	if allAlnum(nil) {
		t.Error("allAlnum(nil) = true, want false")
	}
	if !allAlnum([]byte("abc123")) {
		t.Error("allAlnum(\"abc123\") = false, want true")
	}
	if allAlnum([]byte("abc!23")) {
		t.Error("allAlnum(\"abc!23\") = true, want false")
	}
	if !allSame([]byte("")) {
		t.Error("allSame(\"\") = false, want true (vacuous)")
	}
	if !allSame([]byte("aaaa")) {
		t.Error("allSame(\"aaaa\") = false, want true")
	}
	if allSame([]byte("aaab")) {
		t.Error("allSame(\"aaab\") = true, want false")
	}
	if !boundaryOK([]byte("abc"), 3) {
		t.Error("boundaryOK at end of window = false, want true")
	}
	if !boundaryOK([]byte("abc!"), 3) {
		t.Error("boundaryOK before '!' = false, want true")
	}
	if boundaryOK([]byte("abcd"), 3) {
		t.Error("boundaryOK before 'd' = true, want false")
	}
}
