package entropy

import "testing"

// FuzzNoPanics feeds arbitrary bytes, bounded to <= 1KiB (this package's
// documented contract: bounded candidates only), through every exported
// function and confirms none of them ever panics, regardless of content
// (including invalid UTF-8, all-zero, or all-0xFF input).
func FuzzNoPanics(f *testing.F) {
	seeds := []string{
		"",
		"a",
		"550e8400-e29b-41d4-a716-446655440000",
		"hello_world_this_is_config",
		"\x00\x00\x00\x00",
		"\xff\xff\xff\xff",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"<YOUR_API_KEY>",
		"${SECRET}",
		"{{ token }}",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	opts := []Options{
		{},
		PresetAssignmentValue,
		PresetLooseToken,
		{MinLen: 1, MaxLen: 1 << 10, MinBitsPerByte: 8, RejectUUID: true, RejectHexHash: true, RejectDigits: true, MaxRepeatRun: 1},
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		const maxLen = 1024
		if len(data) > maxLen {
			data = data[:maxLen]
		}
		b := make([]byte, len(data))
		copy(b, data)

		_ = Shannon(b)
		_ = BitsTotal(b)
		_ = Classify(b)
		_ = IsPlaceholder(b)
		for _, o := range opts {
			_ = Secretlike(b, o)
		}
	})
}
