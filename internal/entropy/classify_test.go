package entropy

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Class
	}{
		{"empty", "", ClassUnknown},

		{"uuid lowercase", "550e8400-e29b-41d4-a716-446655440000", ClassUUID},
		{"uuid uppercase", "550E8400-E29B-41D4-A716-446655440000", ClassUUID},
		{"uuid mixed case", "550e8400-E29b-41D4-a716-446655440000", ClassUUID},
		{"uuid wrong dash position not uuid", "550e8400e29b-41d4-a716-446655440000", ClassBase64ish},

		{"git sha 40 hex lowercase", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", ClassHexHash},
		{"git sha 40 hex uppercase", "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3", ClassHexHash},
		{"sha256 64 hex", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", ClassHexHash},
		{"md5 32 hex", "5d41402abc4b2a76b9719d911017c592", ClassHexHash},
		{"39 hex not a hash length", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd", ClassBase64ish},

		{"pure digits", "1234567890123456", ClassDigits},
		{"pure digits short", "42", ClassDigits},

		{"base64ish random", "Xk9mP2vQ7Rt4Ws8LbN3jF6hZ1cYdA0eB5gC", ClassBase64ish},
		{"base64 with padding and slashes", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo9Lz8=", ClassBase64ish},

		{"english word compound", "hello_world_this_is_config", ClassWordlike},
		{"plain lowercase word", "configuration", ClassWordlike},
		{"lowercase with hyphen", "my-config-value", ClassWordlike},

		{"uppercase word not wordlike", "CONFIGURATION", ClassBase64ish},
		{"word with digit not wordlike", "config1", ClassBase64ish},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify([]byte(tc.in)); got != tc.want {
				t.Errorf("Classify(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestClassifyNilAndEmpty(t *testing.T) {
	if got := Classify(nil); got != ClassUnknown {
		t.Errorf("Classify(nil) = %v, want ClassUnknown", got)
	}
	if got := Classify([]byte{}); got != ClassUnknown {
		t.Errorf("Classify(empty) = %v, want ClassUnknown", got)
	}
}
