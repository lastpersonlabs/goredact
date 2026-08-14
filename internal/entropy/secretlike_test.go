package entropy

import "testing"

func TestSecretlikePresetAssignmentValue(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"random-looking 32-char base62", "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU", true},
		{"english compound not secretlike", "hello_world_this_is_config", false},
		{"uuid rejected structurally", "550e8400-e29b-41d4-a716-446655440000", false},
		{"40-hex git sha rejected structurally", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", false},
		{"pure digits rejected structurally", "90182736451029384756", false},
		{"too short", "Ab1$xQ9", false},
		{"placeholder value", "your-api-key-goes-here-123456", false},
		{"repeated char run over limit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"low entropy repeated pattern", "abababababababababababababab", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Secretlike([]byte(tc.in), PresetAssignmentValue); got != tc.want {
				t.Errorf("Secretlike(%q, PresetAssignmentValue) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSecretlikePresetLooseToken(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"random-looking 32-char base62", "aZ9kQ2vR7wL4mN8pX1sT6bF3jH0cD5yU", true},
		{"hex hash allowed under loose preset", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", true},
		{"uuid rejected structurally", "550e8400-e29b-41d4-a716-446655440000", false},
		{"pure digits rejected structurally", "90182736451029384756", false},
		{"csv.next() call is not a token", "csv.next()", false},
		{"placeholder cursor", "<YOUR_TOKEN>", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Secretlike([]byte(tc.in), PresetLooseToken); got != tc.want {
				t.Errorf("Secretlike(%q, PresetLooseToken) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSecretlikeLengthBounds(t *testing.T) {
	opts := Options{MinLen: 5, MaxLen: 10}
	if Secretlike([]byte("abcd"), opts) {
		t.Error("Secretlike below MinLen should be false")
	}
	if Secretlike([]byte("abcdefghijk"), opts) {
		t.Error("Secretlike above MaxLen should be false")
	}
}

func TestSecretlikeMaxRepeatRun(t *testing.T) {
	opts := Options{MaxRepeatRun: 3}
	if Secretlike([]byte("aaaaXbYcZd1e2f3g4"), opts) {
		t.Error("Secretlike with repeat run over MaxRepeatRun should be false")
	}
}

func TestSecretlikeZeroOptionsOnlyAppliesPlaceholderAndWordlikeChecks(t *testing.T) {
	// With every Options field at its zero value, Secretlike still
	// rejects placeholders and word-like values but imposes no length,
	// entropy, or shape rejection.
	if Secretlike([]byte("changeme"), Options{}) {
		t.Error("zero-value Options should still reject placeholders")
	}
	if Secretlike([]byte("hello_world"), Options{}) {
		t.Error("zero-value Options should still reject word-like values")
	}
	if !Secretlike([]byte("42"), Options{}) {
		t.Error("zero-value Options should accept an otherwise-unremarkable short value")
	}
}
