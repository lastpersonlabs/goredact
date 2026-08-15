package validators

import "testing"

// Synthetic fixture bodies for GenericSecretAssignment. Never derived
// from real credentials.
const (
	deepGenericBody1 = "rwsmyxydQrWgPCi4wtEP7qi75tWU"
	deepGenericBody2 = "9rtyiWofxFYcbVNBebGDBV2h"
	deepGenericBody3 = "69cv5BW8EwnNoBtGGe8aNAHh7NWfiM1O"
	deepGenericBody4 = "FlOJfSS2xyK7tLQh9bZU"
	deepGenericBody5 = "0cXGCcKnSPVS3qsTbU7H3D8YTfkFdL"
)

func TestGenericSecretAssignment(t *testing.T) {
	cases := []validatorCase{
		{
			name:      "gap-tolerant phrase before operator (AWS Secret Key)",
			window:    "AWS Secret Key = " + deepGenericBody1,
			trigStart: len("AWS "),
			trigEnd:   len("AWS Secret"),
			wantOK:    true,
			wantStart: len("AWS Secret Key = "),
			wantEnd:   len("AWS Secret Key = ") + len(deepGenericBody1),
		},
		{
			name:      "gap-tolerant phrase with colon separator (Client Auth Token)",
			window:    "Client Auth Token: " + deepGenericBody2,
			trigStart: len("Client "),
			trigEnd:   len("Client Auth"),
			wantOK:    true,
			wantStart: len("Client Auth Token: "),
			wantEnd:   len("Client Auth Token: ") + len(deepGenericBody2),
		},
		{
			name:      "tight zero-gap parse (bare key trigger)",
			window:    "key = " + deepGenericBody3,
			trigStart: 0,
			trigEnd:   3,
			wantOK:    true,
			wantStart: len("key = "),
			wantEnd:   len("key = ") + len(deepGenericBody3),
		},
		{
			name:      "JSON-quoted-key shape (credential)",
			window:    `{"credential": "` + deepGenericBody4 + `"}`,
			trigStart: len(`{"`),
			trigEnd:   len(`{"credential`),
			wantOK:    true,
			wantStart: len(`{"credential": "`),
			wantEnd:   len(`{"credential": "`) + len(deepGenericBody4),
		},
		{
			name:      "no separator gap at all (creds=)",
			window:    "creds=" + deepGenericBody5,
			trigStart: 0,
			trigEnd:   5,
			wantOK:    true,
			wantStart: len("creds="),
			wantEnd:   len("creds=") + len(deepGenericBody5),
		},
		{
			name:      "preceding alnum rejected (key inside monkey)",
			window:    "the monkey business",
			trigStart: len("the mon"),
			trigEnd:   len("the mon") + 3,
			wantOK:    false,
		},
		{
			name:      "keyword with no operator within gap rejected",
			window:    "keyboard shortcuts are useful for this workflow",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "alpha-space-only value rejected (author = 'Alice Programmer')",
			window:    "author = 'Alice Programmer'",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "indirect value rejected (os.environ.get)",
			window:    "access = os.environ.get('SECRET')",
			trigStart: 0,
			trigEnd:   6,
			wantOK:    false,
		},
		{
			name:      "UUID value rejected",
			window:    "credential_id = 550e8400-e29b-41d4-a716-446655440000",
			trigStart: 0,
			trigEnd:   10,
			wantOK:    false,
		},
		{
			name:      "value too short rejected",
			window:    "key = short",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
		{
			name:      "all-identical value rejected as placeholder",
			window:    "secret = " + repeat('a', 28),
			trigStart: 0,
			trigEnd:   6,
			wantOK:    false,
		},
		{
			name:      "empty inline backtick assignment followed by unrelated text rejected",
			window:    "`key=`" + deepGenericBody1 + "`",
			trigStart: len("`"),
			trigEnd:   len("`key"),
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window",
			window:    "key",
			trigStart: 0,
			trigEnd:   3,
			wantOK:    false,
		},
	}
	runValidatorCases(t, GenericSecretAssignment, cases)
}

func TestGenericSecretAssignmentNeverPanics(t *testing.T) {
	aiRunNeverPanics(t, "GenericSecretAssignment", GenericSecretAssignment, []string{
		"", "k", "key", "key ", "key = ", "key=" + deepGenericBody3,
		"AWS Secret Key = " + deepGenericBody1,
		"credential_id = 550e8400-e29b-41d4-a716-446655440000",
		"key" + repeat('a', 30), "\x00\x00\x00\x00\x00",
	})
}

func TestIsWeakGapByte(t *testing.T) {
	accept := []byte{'a', 'Z', '0', '_', ' ', '\t', '.', '-'}
	for _, c := range accept {
		if !isWeakGapByte(c) {
			t.Errorf("isWeakGapByte(%q) = false, want true", c)
		}
	}
	reject := []byte{'=', ':', '"', '\'', '\n', '!', '/'}
	for _, c := range reject {
		if isWeakGapByte(c) {
			t.Errorf("isWeakGapByte(%q) = true, want false", c)
		}
	}
}

func TestSkipWeakGap(t *testing.T) {
	cases := []struct {
		window string
		pos    int
		want   int
	}{
		{"= value", 0, 0},    // no gap, operator immediately
		{" = value", 0, 1},   // one space gap
		{"or = value", 0, 3}, // word gap then space then operator
		{"", 0, 0},           // empty window
		{"abcdefghijklmnopqrstuvwxyz", 0, weakAssignmentGapMax}, // capped at max
	}
	for _, tc := range cases {
		got := skipWeakGap([]byte(tc.window), tc.pos)
		if got != tc.want {
			t.Errorf("skipWeakGap(%q, %d) = %d, want %d", tc.window, tc.pos, got, tc.want)
		}
	}
}
