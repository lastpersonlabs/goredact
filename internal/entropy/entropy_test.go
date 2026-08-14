package entropy

import (
	"math"
	"testing"
)

func almostEqual(a, b, eps float64) bool {
	return math.Abs(a-b) <= eps
}

func TestShannonKnownDistributions(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want float64
	}{
		{"empty", "", 0},
		{"single byte", "a", 0},
		{"all identical", "aaaaaaaa", 0},
		// Two symbols, uniform: exactly 1 bit/byte.
		{"two symbols uniform", "abababab", 1},
		// Four symbols, uniform: exactly 2 bits/byte.
		{"four symbols uniform", "abcdabcdabcdabcd", 2},
		// 256 distinct byte values, each once: exactly 8 bits/byte.
		{"all 256 byte values once", string(allBytes()), 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Shannon([]byte(tc.in))
			if !almostEqual(got, tc.want, 1e-9) {
				t.Errorf("Shannon(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestShannonNilAndEmptyAgree(t *testing.T) {
	if Shannon(nil) != 0 {
		t.Errorf("Shannon(nil) = %v, want 0", Shannon(nil))
	}
	if Shannon([]byte{}) != 0 {
		t.Errorf("Shannon([]byte{}) = %v, want 0", Shannon([]byte{}))
	}
}

func TestBitsTotal(t *testing.T) {
	b := []byte("abababab") // Shannon == 1, len == 8
	got := BitsTotal(b)
	want := 8.0
	if !almostEqual(got, want, 1e-9) {
		t.Errorf("BitsTotal(%q) = %v, want %v", b, got, want)
	}
	if BitsTotal(nil) != 0 {
		t.Errorf("BitsTotal(nil) = %v, want 0", BitsTotal(nil))
	}
}

func TestLongestRepeatRun(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"a", 1},
		{"aaaa", 4},
		{"aabbaaa", 3},
		{"abcabc", 1},
		{"xxxxy", 4},
	}
	for _, tc := range cases {
		if got := longestRepeatRun([]byte(tc.in)); got != tc.want {
			t.Errorf("longestRepeatRun(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
