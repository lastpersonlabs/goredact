package ahocorasick

import (
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
)

// hit is a match with its absolute (whole-input) exclusive end offset.
type hit struct {
	pat int
	end int
}

func sortHits(hs []hit) {
	sort.Slice(hs, func(i, j int) bool {
		if hs[i].end != hs[j].end {
			return hs[i].end < hs[j].end
		}
		return hs[i].pat < hs[j].pat
	})
}

func hitsEqual(a, b []hit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func foldString(s string) string {
	b := []byte(s)
	for i := range b {
		b[i] = foldTab[b[i]]
	}
	return string(b)
}

// refMatches is the naive reference matcher: a strings.Index loop with
// ASCII case folding for CaseFold patterns.
func refMatches(patterns []Pattern, input []byte) []hit {
	var hs []hit
	for pi, p := range patterns {
		hay, needle := string(input), p.Literal
		if p.CaseFold {
			hay, needle = foldString(hay), foldString(needle)
		}
		for off := 0; off <= len(hay); {
			j := strings.Index(hay[off:], needle)
			if j < 0 {
				break
			}
			start := off + j
			hs = append(hs, hit{pi, start + len(needle)})
			off = start + 1
		}
	}
	sortHits(hs)
	return hs
}

// scanChunks scans input split into chunks, carrying State across chunk
// boundaries, and returns matches with reconstructed absolute end offsets.
func scanChunks(a *Automaton, chunks [][]byte) []hit {
	var hs []hit
	var st State
	base := 0
	for _, ch := range chunks {
		st = a.Scan(st, ch, func(p, e int) bool {
			hs = append(hs, hit{p, base + e})
			return true
		})
		base += len(ch)
	}
	sortHits(hs)
	return hs
}

func mustCompile(t testing.TB, patterns []Pattern) *Automaton {
	t.Helper()
	a, err := Compile(patterns)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return a
}

type testCase struct {
	name     string
	patterns []Pattern
	inputs   []string
}

func correctnessCases() []testCase {
	return []testCase{
		{
			name: "classic-overlapping",
			patterns: []Pattern{
				{Literal: "he"}, {Literal: "she"}, {Literal: "hers"}, {Literal: "his"},
			},
			inputs: []string{
				"ushers", "she sells his hershey", "hishershe", "ahishers",
				"HE SHE HERS", "xxxxxxxx", "", "h", "hers",
			},
		},
		{
			name: "classic-overlapping-folded",
			patterns: []Pattern{
				{Literal: "he", CaseFold: true}, {Literal: "she", CaseFold: true},
				{Literal: "hers", CaseFold: true}, {Literal: "his", CaseFold: true},
			},
			inputs: []string{"uSHeRS", "SHE sells HIS HeRsHeY", "HiShErShE", "aHIShers"},
		},
		{
			name: "duplicate-literals-mixed-fold",
			patterns: []Pattern{
				{Literal: "Token"}, {Literal: "Token", CaseFold: true},
				{Literal: "token", CaseFold: true}, {Literal: "token"},
			},
			inputs: []string{
				"Token token TOKEN toKen", "xTokenx", "TOKEntoken", "toketoken",
			},
		},
		{
			name: "prefix-suffix-nesting",
			patterns: []Pattern{
				{Literal: "a"}, {Literal: "ab"}, {Literal: "abc"}, {Literal: "abcd"},
				{Literal: "bc"}, {Literal: "c"}, {Literal: "bcd", CaseFold: true},
			},
			inputs: []string{"abcdabcabcd", "aaaa", "abcabcABCD", "dcba", "ababab"},
		},
		{
			name: "single-byte",
			patterns: []Pattern{
				{Literal: "a"}, {Literal: " "}, {Literal: "\x00"}, {Literal: "z", CaseFold: true},
			},
			inputs: []string{"a z\x00Z a", "\x00\x00", "ZZZZ", "b"},
		},
		{
			name: "long-64-byte",
			patterns: []Pattern{
				{Literal: strings.Repeat("ab", 32)},
				{Literal: strings.Repeat("AB", 32), CaseFold: true},
				{Literal: "ab"},
			},
			inputs: []string{
				strings.Repeat("ab", 40),
				strings.Repeat("aB", 40),
				strings.Repeat("ab", 31) + "ba" + strings.Repeat("ab", 33),
			},
		},
	}
}

func TestScanMatchesReference(t *testing.T) {
	for _, tc := range correctnessCases() {
		t.Run(tc.name, func(t *testing.T) {
			a := mustCompile(t, tc.patterns)
			for _, in := range tc.inputs {
				got := scanChunks(a, [][]byte{[]byte(in)})
				want := refMatches(tc.patterns, []byte(in))
				if !hitsEqual(got, want) {
					t.Errorf("input %q: got %v, want %v", in, got, want)
				}
			}
		})
	}
}

func TestScanMatchesReferenceRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(95))
	patterns := []Pattern{
		{Literal: "he"}, {Literal: "she", CaseFold: true}, {Literal: "hers"},
		{Literal: "his", CaseFold: true}, {Literal: "a"}, {Literal: "AB"},
		{Literal: "ab", CaseFold: true}, {Literal: "bab"}, {Literal: "ABBA", CaseFold: true},
	}
	a := mustCompile(t, patterns)
	alphabet := []byte("abABheErRsS ")
	for trial := 0; trial < 200; trial++ {
		n := rng.Intn(300)
		in := make([]byte, n)
		for i := range in {
			in[i] = alphabet[rng.Intn(len(alphabet))]
		}
		got := scanChunks(a, [][]byte{in})
		want := refMatches(patterns, in)
		if !hitsEqual(got, want) {
			t.Fatalf("trial %d input %q: got %v, want %v", trial, in, got, want)
		}
	}
}

// splitEverywhere checks that splitting the input at every boundary and
// into random 1..7-byte pieces yields the identical match set as a
// one-shot scan.
func TestChunkBoundaryResumability(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	cases := correctnessCases()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := mustCompile(t, tc.patterns)
			for _, ins := range tc.inputs {
				in := []byte(ins)
				want := refMatches(tc.patterns, in)
				if one := scanChunks(a, [][]byte{in}); !hitsEqual(one, want) {
					t.Fatalf("one-shot on %q: got %v, want %v", in, one, want)
				}
				// Every two-piece split.
				for cut := 0; cut <= len(in); cut++ {
					got := scanChunks(a, [][]byte{in[:cut], in[cut:]})
					if !hitsEqual(got, want) {
						t.Fatalf("split at %d of %q: got %v, want %v", cut, in, got, want)
					}
				}
				// Random 1..7-byte pieces, several times.
				for trial := 0; trial < 10; trial++ {
					var chunks [][]byte
					for pos := 0; pos < len(in); {
						sz := 1 + rng.Intn(7)
						if pos+sz > len(in) {
							sz = len(in) - pos
						}
						chunks = append(chunks, in[pos:pos+sz])
						pos += sz
					}
					got := scanChunks(a, chunks)
					if !hitsEqual(got, want) {
						t.Fatalf("random pieces of %q: got %v, want %v", in, got, want)
					}
				}
			}
		})
	}
}

// A match spanning a chunk boundary must report end < pattern length in
// the second chunk.
func TestBoundarySpanningEndOffset(t *testing.T) {
	a := mustCompile(t, []Pattern{{Literal: "secret", CaseFold: true}})
	st := a.Scan(0, []byte("xxSEC"), func(int, int) bool {
		t.Fatal("unexpected match in first chunk")
		return false
	})
	var got []hit
	a.Scan(st, []byte("retyy"), func(p, e int) bool {
		got = append(got, hit{p, e})
		return true
	})
	if len(got) != 1 || got[0] != (hit{0, 3}) {
		t.Fatalf("got %v, want [{0 3}]", got)
	}
}

func TestEarlyStop(t *testing.T) {
	patterns := []Pattern{{Literal: "ab"}, {Literal: "b", CaseFold: true}}
	a := mustCompile(t, patterns)
	calls := 0
	a.Scan(0, []byte("ababab"), func(p, e int) bool {
		calls++
		return false
	})
	if calls != 1 {
		t.Fatalf("fn called %d times after returning false, want 1", calls)
	}
}

func TestCompileErrors(t *testing.T) {
	if _, err := Compile(nil); err == nil {
		t.Error("Compile(nil) should fail")
	}
	if _, err := Compile([]Pattern{}); err == nil {
		t.Error("Compile(empty) should fail")
	}
	if _, err := Compile([]Pattern{{Literal: "ok"}, {Literal: ""}}); err == nil {
		t.Error("empty literal should fail")
	}
	// State-count overflow: distinct long random-ish literals whose trie
	// exceeds 65536 nodes.
	var big []Pattern
	for i := 0; i < 700; i++ {
		lit := make([]byte, 100)
		r := rand.New(rand.NewSource(int64(i)))
		for j := range lit {
			lit[j] = byte(r.Intn(256))
		}
		big = append(big, Pattern{Literal: string(lit)})
	}
	if _, err := Compile(big); err == nil {
		t.Error("state-count overflow should fail")
	}
}

func TestScanZeroAllocs(t *testing.T) {
	patterns := benchPatterns()
	a := mustCompile(t, patterns)
	// Matching-heavy input.
	input := []byte(strings.Repeat("password SECRET token ghp_abc AKIA xoxb- api_key ", 40))
	matches := 0
	fn := func(p, e int) bool {
		matches++
		return true
	}
	allocs := testing.AllocsPerRun(100, func() {
		a.Scan(0, input, fn)
	})
	if allocs != 0 {
		t.Fatalf("Scan allocated %.1f times per run, want 0", allocs)
	}
	if matches == 0 {
		t.Fatal("expected matches on matching-heavy input")
	}
}

func TestConcurrentScans(t *testing.T) {
	patterns := benchPatterns()
	a := mustCompile(t, patterns)
	input := []byte(strings.Repeat("the password is secret; Bearer TOKEN ghp_x AKIAxxxx ", 100))
	want := len(refMatches(patterns, input))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for iter := 0; iter < 20; iter++ {
				got := 0
				var st State
				for pos := 0; pos < len(input); {
					sz := 1 + rng.Intn(97)
					if pos+sz > len(input) {
						sz = len(input) - pos
					}
					st = a.Scan(st, input[pos:pos+sz], func(int, int) bool {
						got++
						return true
					})
					pos += sz
				}
				if got != want {
					t.Errorf("goroutine %d: got %d matches, want %d", seed, got, want)
					return
				}
			}
		}(int64(g))
	}
	wg.Wait()
}
