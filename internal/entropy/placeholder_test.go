package entropy

import "testing"

func TestIsPlaceholder(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// Positives: keyword substrings, case-insensitive.
		{"example substring", "my-example-key-12345", true},
		{"changeme whole", "changeme", true},
		{"change_me mixed case", "CHANGE_ME", true},
		{"password substring", "SuperPassword123456", true},
		{"your- prefix style", "your-api-key-here", true},
		{"your_ prefix style", "YOUR_SECRET_HERE", true},
		{"placeholder substring", "placeholder-value-xyz", true},
		{"dummy substring", "dummy-token-abcdefgh", true},
		{"sample substring", "sample-credential-99", true},
		{"test substring", "test-token-1234567890", true},
		{"todo substring", "TODO-fill-this-in", true},
		{"xxxx run", "xxxxxxxxxxxxxxxx", true},
		{"0000 substring", "0000000000000000", true},
		{"1234 substring embedded", "abc1234567890", true},
		{"abcd substring embedded", "prefixabcdsuffix1234", true},
		{"secret whole value only", "secret", true},

		// Positives: structural.
		{"single repeated char", "aaaaaaaaaaaaaaaaaaaa", true},
		{"angle bracket token", "<YOUR_API_KEY>", true},
		{"angle bracket redacted", "<redacted>", true},
		{"dollar brace template", "${API_KEY}", true},
		{"double brace template", "{{ secrets.token }}", true},
		{"bare shell variable", "$DB_PASSWORD", true},
		{"command substitution", "$(cat secret)", true},
		{"dollar with one further dollar sign", "$foo$bar", true},
		{"ascending letters", "abcdefghijklmnop", true},
		{"ascending digits", "234567890123456", true},
		{"keyboard qwerty", "qwertyuiopasdfgh", true},
		{"empty", "", true},

		// Negatives: real-looking secrets must NOT be placeholders.
		{"random base62", "Xk9mP2vQ7Rt4Ws8LbN3jF6hZ1cYdA0eB5gC", false},
		{"random hex-ish mixed", "9fA3dE71cB40aF98eD22bC15", false},
		{"random with symbols", "gT7!kP9@qR2#mN4$wZ8", false},
		{"long random token", "k3JmQz9XpL2vN7wR5tY8bC1sD4fA6hE0uI", false},
		{"base64 with slashes not placeholder", "QW1hem9uUzNBY2Nlc3NLZXk3Nzc5", false},
		{"secret as substring not whole value", "topsecretvaluehere123", false},
		{"bcrypt hash", "$2b$12$LJ3mNIVs1BQpNCoQpFHzC.qXvlyfvOmYFXQiP34XLU7T4TWTfxLGO", false},
		{"argon2id hash", "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub7bXwRWJTmaaJObG", false},
		{"sha512crypt hash", "$6$rounds=5000$saltstring$rZP7Pl9CBGJvbrX2BbfN.T.QaMFxwHUYA0FfWNIWJZucfLpJI9j6TjMPCUsF4Uxm3ZxoNIxYQVMz0oRnHmXPr1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPlaceholder([]byte(tc.in)); got != tc.want {
				t.Errorf("IsPlaceholder(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
