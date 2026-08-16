// Package ahocorasick implements an allocation-free, resumable
// Aho–Corasick multi-pattern matcher over bytes.
//
// # Design
//
// Patterns are split by case sensitivity into two independent
// sub-automata:
//
//   - an "exact" automaton built over the unfolded pattern bytes for
//     case-sensitive patterns, scanned over the raw input bytes;
//   - a "folded" automaton built over ASCII-case-folded pattern bytes
//     ('A'..'Z' → 'a'..'z') for CaseFold patterns, scanned over folded
//     input bytes.
//
// Running both automata in a single interleaved pass keeps case-sensitive
// semantics exact (no post-verification, which cannot be done for
// boundary-spanning matches without buffering) while remaining
// allocation-free on the scan path.
//
// Each sub-automaton is compiled into a dense DFA: the classic trie plus
// BFS fail links are resolved at Compile time into a flat
// next[state*256+byte] uint16 table, and dictionary suffix (output) links
// are flattened into a per-state list of pattern indexes, so every pattern
// ending at a position is reported, including overlapping matches. Scan is
// therefore one table lookup per byte per sub-automaton with no branching
// on fail chains — optimised for mostly-non-matching input.
//
// State packs the two sub-automaton state indexes as two uint16 halves
// (low 16 bits: exact automaton, high 16 bits: folded automaton). The zero
// State is both roots. Compile returns an error if either sub-automaton
// would exceed 65536 states.
package ahocorasick

import (
	"errors"
	"fmt"
)

// Pattern is a literal to search for.
type Pattern struct {
	Literal  string // non-empty
	CaseFold bool   // ASCII case-insensitive
}

// State carries matcher position across chunk boundaries. The zero value
// is the root (start) state. Low 16 bits hold the exact (case-sensitive)
// sub-automaton state, high 16 bits the folded sub-automaton state.
type State uint32

// maxStates is the per-sub-automaton state limit imposed by the uint16
// state representation packed into State.
const maxStates = 1 << 16

// identTab and foldTab translate input bytes for the exact and folded
// sub-automata respectively.
var identTab, foldTab [256]byte

func init() {
	for i := 0; i < 256; i++ {
		identTab[i] = byte(i)
		foldTab[i] = byte(i)
		if i >= 'A' && i <= 'Z' {
			foldTab[i] = byte(i) + ('a' - 'A')
		}
	}
}

// matcher is one compiled sub-automaton: a fully resolved dense DFA.
type matcher struct {
	// next[state<<8|tab[b]] is the state after consuming input byte b.
	next []uint16
	// State s emits pattern indexes outs[outStart[s]:outStart[s+1]].
	outStart []uint32
	outs     []int32
	// tab translates each input byte before the transition lookup
	// (identity for the exact automaton, ASCII fold for the folded one).
	tab *[256]byte
}

// Automaton is an immutable compiled pattern set. It is safe for
// concurrent Scan calls with independent States.
type Automaton struct {
	exact *matcher // case-sensitive patterns, nil if none
	fold  *matcher // case-folded patterns, nil if none
}

// Compile builds an Automaton from patterns. It returns an error if the
// slice is empty, any literal is empty, or the state count of either
// internal sub-automaton would overflow the packed State representation.
func Compile(patterns []Pattern) (*Automaton, error) {
	if len(patterns) == 0 {
		return nil, errors.New("ahocorasick: at least one pattern is required")
	}
	var eb, fb *builder
	for i, p := range patterns {
		if p.Literal == "" {
			return nil, fmt.Errorf("ahocorasick: pattern %d has an empty literal", i)
		}
		if p.CaseFold {
			if fb == nil {
				fb = newBuilder()
			}
			if err := fb.insert(p.Literal, &foldTab, int32(i)); err != nil {
				return nil, err
			}
		} else {
			if eb == nil {
				eb = newBuilder()
			}
			if err := eb.insert(p.Literal, &identTab, int32(i)); err != nil {
				return nil, err
			}
		}
	}
	a := &Automaton{}
	if eb != nil {
		a.exact = eb.finish(&identTab)
	}
	if fb != nil {
		a.fold = fb.finish(&foldTab)
	}
	return a, nil
}

// Scan advances through chunk from state s, invoking fn for every
// occurrence of every pattern (including overlapping matches and matches
// that span the boundary between the previous chunk and this one) with the
// pattern index (into the Compile slice) and the exclusive end offset
// within chunk (which may be smaller than the pattern length for
// boundary-spanning matches). fn returning false stops the scan early.
// Scan performs no heap allocation.
//
// An early stop abandons the rest of the scan outright: other matches
// ending at the same byte are not delivered, the caller is not told how
// far into chunk the scan advanced, and the returned State is therefore
// not meaningful to resume from. Return false only to answer a pure
// "does any pattern occur?" query (as containsAnywhereKeyword does);
// resumable streaming callers must always return true (as the engine
// does).
func (a *Automaton) Scan(s State, chunk []byte, fn func(pattern int, end int) bool) State {
	es := uint32(s) & 0xffff
	fs := uint32(s) >> 16
	switch {
	case a.fold == nil:
		es, _ = a.exact.scan(es, chunk, fn)
		return State(es | fs<<16)
	case a.exact == nil:
		fs, _ = a.fold.scan(fs, chunk, fn)
		return State(es | fs<<16)
	}
	// Dual interleaved scan: both sub-automata advance byte by byte so an
	// early stop leaves them at the same input position.
	e, f := a.exact, a.fold
	eNext, eStart, eOuts := e.next, e.outStart, e.outs
	fNext, fStart, fOuts := f.next, f.outStart, f.outs
	ftab := f.tab
	for i := 0; i < len(chunk); i++ {
		b := chunk[i]
		es = uint32(eNext[int(es)<<8|int(b)])
		fs = uint32(fNext[int(fs)<<8|int(ftab[b])])
		if o, oe := eStart[es], eStart[es+1]; o != oe {
			for ; o < oe; o++ {
				if !fn(int(eOuts[o]), i+1) {
					return State(es | fs<<16)
				}
			}
		}
		if o, oe := fStart[fs], fStart[fs+1]; o != oe {
			for ; o < oe; o++ {
				if !fn(int(fOuts[o]), i+1) {
					return State(es | fs<<16)
				}
			}
		}
	}
	return State(es | fs<<16)
}

// scan runs a single sub-automaton over chunk. It returns the resulting
// state and false if fn stopped the scan early.
func (m *matcher) scan(st uint32, chunk []byte, fn func(pattern int, end int) bool) (uint32, bool) {
	next, start, outs, tab := m.next, m.outStart, m.outs, m.tab
	for i := 0; i < len(chunk); i++ {
		st = uint32(next[int(st)<<8|int(tab[chunk[i]])])
		if o, oe := start[st], start[st+1]; o != oe {
			for ; o < oe; o++ {
				if !fn(int(outs[o]), i+1) {
					return st, false
				}
			}
		}
	}
	return st, true
}

// builder accumulates a byte trie before DFA conversion.
type builder struct {
	// edges[s][b] is the trie child of s on byte b, or -1.
	edges [][256]int32
	// out[s] holds pattern indexes whose literal ends exactly at s.
	out [][]int32
}

func newBuilder() *builder {
	b := &builder{}
	b.addNode() // root = state 0
	return b
}

func (b *builder) addNode() int32 {
	var e [256]int32
	for i := range e {
		e[i] = -1
	}
	b.edges = append(b.edges, e)
	b.out = append(b.out, nil)
	return int32(len(b.edges) - 1)
}

// insert adds literal (translated through tab) ending at global pattern
// index pat. It errors if the trie would exceed the packed-state limit.
func (b *builder) insert(literal string, tab *[256]byte, pat int32) error {
	s := int32(0)
	for i := 0; i < len(literal); i++ {
		c := tab[literal[i]]
		t := b.edges[s][c]
		if t < 0 {
			if len(b.edges) >= maxStates {
				return fmt.Errorf("ahocorasick: pattern set needs more than %d states", maxStates)
			}
			t = b.addNode()
			b.edges[s][c] = t
		}
		s = t
	}
	b.out[s] = append(b.out[s], pat)
	return nil
}

// finish resolves fail links via BFS, flattens dictionary suffix outputs
// into each state's output list, and produces the dense DFA tables.
func (b *builder) finish(tab *[256]byte) *matcher {
	n := len(b.edges)
	next := make([]uint16, n*256)
	fail := make([]int32, n)
	queue := make([]int32, 0, n)

	// Root: missing edges self-loop; children fail to root.
	for c := 0; c < 256; c++ {
		if s := b.edges[0][c]; s >= 0 {
			next[c] = uint16(s)
			queue = append(queue, s)
		}
	}
	for qi := 0; qi < len(queue); qi++ {
		r := queue[qi]
		// fail[r] is shallower, so its output list is already flattened;
		// appending it makes out[r] the full dictionary-suffix set.
		if fo := b.out[fail[r]]; len(fo) > 0 {
			b.out[r] = append(b.out[r], fo...)
		}
		base := int(r) << 8
		fbase := int(fail[r]) << 8
		for c := 0; c < 256; c++ {
			if s := b.edges[r][c]; s >= 0 {
				fail[s] = int32(next[fbase|c])
				next[base|c] = uint16(s)
				queue = append(queue, s)
			} else {
				next[base|c] = next[fbase|c]
			}
		}
	}

	outStart := make([]uint32, n+1)
	total := 0
	for i, o := range b.out {
		outStart[i] = uint32(total)
		total += len(o)
	}
	outStart[n] = uint32(total)
	outs := make([]int32, 0, total)
	for _, o := range b.out {
		outs = append(outs, o...)
	}
	return &matcher{next: next, outStart: outStart, outs: outs, tab: tab}
}
