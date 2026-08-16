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

		// Regression: a chain of concatenated shell variables has 2+ '$'
		// separators just like a real hash, but its first field is not a
		// recognized crypt algorithm identifier, so it must still be
		// treated as a placeholder/template reference rather than waved
		// through as a modular-crypt hash.
		{"concatenated shell variables, not modular crypt", "$databaseUser$databasePass$environmentName", true},

		// Regression: a leading '$' alone must not make a value a
		// placeholder. Hash formats beyond the classic crypt(3) set, and
		// arbitrary secrets that merely start with '$', all fail
		// shell-variable grammar and must stay redactable.
		{"apr1 htpasswd hash", "$apr1$x8sl9u4T$qBcNpSoGDBQ3zMSOMCJVt0", false},
		{"pbkdf2-sha256 passlib hash", "$pbkdf2-sha256$29000$V0rJmRPiPCdkzBmDMEbo3Q$FyLs7omUppxzXkARJQSl.ozcEOhgp3tNgNsKIWpoQt0", false},
		{"scrypt passlib hash", "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CmdRSCdEBsjjJxD", false},
		{"dollar-prefixed secret with symbols", "$Xk9!mP2vQ7Rt4Ws8LbN3jF6hZ1cY", false},
		{"dollar then punctuation", "$!notavariable9fA3dE71cB40aF98eD", false},
		{"dollar then digit-led field", "$9fA3dE71cB40aF98eD22bC15xYwQ", false},
		// A '$' followed by pure alphanumerics has exactly the grammar of
		// a shell variable ("$DB_PASSWORD"), so it stays classified as a
		// reference — the one deliberately ambiguous case.
		{"dollar then alphanumerics reads as shell variable", "$Xk9mP2vQ7Rt4Ws8LbN3jF6hZ1cY", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPlaceholder([]byte(tc.in)); got != tc.want {
				t.Errorf("IsPlaceholder(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsModularCryptHash(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"bcrypt 2b", "$2b$12$LJ3mNIVs1BQpNCoQpFHzC.qXvlyfvOmYFXQiP34XLU7T4TWTfxLGO", true},
		{"bcrypt 2a", "$2a$10$N9qo8uLOickgx2ZMRZoMy.Mrq4gJXY3M3G8L3D1e3H3fJk9m1e3H3", true},
		{"argon2id", "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub7bXwRWJTmaaJObG", true},
		{"sha512crypt with rounds", "$6$rounds=5000$saltstring$rZP7Pl9CBGJvbrX2BbfN.T.QaMFxwHUYA0FfWNIWJZucfLpJI9j6TjMPCUsF4Uxm3ZxoNIxYQVMz0oRnHmXPr1", true},
		{"md5crypt", "$1$salt$qJH7.N4xYta3aEG/dfqo/0", true},
		{"apr1 htpasswd", "$apr1$x8sl9u4T$qBcNpSoGDBQ3zMSOMCJVt0", true},
		{"scrypt numeric id", "$7$CU..../....fCyLEkXWLJ9qEHhEwUnT41$Mia3ZDvE0Tj7Yr9DiKTQAV6RVFWSsvyzYJ9Dua1WvY4", true},
		{"pbkdf2-sha512 passlib", "$pbkdf2-sha512$25000$LyWkFMIYo7T2PqfUmnMuBQ$WlTLDwSjIeyHTVdVIvBAF5KUqXXX", true},
		{"concatenated shell variables", "$databaseUser$databasePass$environmentName", false},
		{"bare shell variable", "$DB_PASSWORD", false},
		{"single dollar field, no id", "$", false},
		{"unrecognized id with two fields", "$unknown$field", false},
		{"empty", "", false},
		{"no leading dollar", "2b$12$abc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsModularCryptHash([]byte(tc.in)); got != tc.want {
				t.Errorf("IsModularCryptHash(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
