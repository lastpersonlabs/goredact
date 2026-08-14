package ahocorasick

import (
	"testing"
)

// fuzzPatterns is a fixed pattern set exercising overlaps, nesting,
// duplicates, and mixed case sensitivity.
var fuzzPatterns = []Pattern{
	{Literal: "he"}, {Literal: "she", CaseFold: true}, {Literal: "hers"},
	{Literal: "his", CaseFold: true}, {Literal: "a"}, {Literal: "ab"},
	{Literal: "abc", CaseFold: true}, {Literal: "AB"}, {Literal: "BA", CaseFold: true},
	{Literal: "aa"}, {Literal: "token"}, {Literal: "token", CaseFold: true},
	{Literal: "\x00\x01"}, {Literal: "\xff", CaseFold: true},
}

func FuzzScanMatchesReference(f *testing.F) {
	f.Add([]byte("ushers his ABba token TOKEN"))
	f.Add([]byte("aaaaabababcABCabc"))
	f.Add([]byte("\x00\x01\xff\xfe\x00"))
	f.Add([]byte(""))
	a, err := Compile(fuzzPatterns)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		want := refMatches(fuzzPatterns, data)
		got := scanChunks(a, [][]byte{data})
		if !hitsEqual(got, want) {
			t.Fatalf("one-shot mismatch on %q: got %v, want %v", data, got, want)
		}
		// Also check resumability at a mid split.
		if len(data) > 1 {
			cut := len(data) / 2
			got2 := scanChunks(a, [][]byte{data[:cut], data[cut:]})
			if !hitsEqual(got2, want) {
				t.Fatalf("split mismatch on %q at %d: got %v, want %v", data, cut, got2, want)
			}
		}
	})
}
