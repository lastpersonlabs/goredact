package entropy

import "testing"

// wordlikeAlphabetHighEntropy is a candidate whose entire alphabet is
// [a-z_-] (Secretlike's wordlike check runs on it) but whose entropy
// (~4.42 bits/byte) is too high to read as wordlike (the 4.2 ceiling), so
// it lands in ClassBase64ish — the case that used to compute Shannon
// twice (once inside the wordlike check, again for the MinBitsPerByte
// floor).
const wordlikeAlphabetHighEntropy = "kfplqznctdfhqztlasloqwjnmrtzseqxwzjyabcdefghijklmn"

// realisticSecretCandidate is shaped like the mixed-case alphanumeric
// values validators actually see; it does not match any placeholder
// keyword, so IsPlaceholder must run its full keyword check before
// returning false.
const realisticSecretCandidate = "Xk9mP2vQ7Rt4Ws8LbN3jF6hZ1cYdA0eB5gC"

func BenchmarkSecretlikeWordlikeAlphabet(b *testing.B) {
	body := []byte(wordlikeAlphabetHighEntropy)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		Secretlike(body, PresetAssignmentValue)
	}
}

func BenchmarkIsPlaceholderNonPlaceholder(b *testing.B) {
	body := []byte(realisticSecretCandidate)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		IsPlaceholder(body)
	}
}
