package goredact

// Boundary and chunking-equivalence tests: the streaming engine's output
// must be byte-identical no matter how the reader slices the input, for
// secrets beginning or ending at every possible read boundary.

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"strings"
	"testing"
)

func isASCIIAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// boundaryConfig builds a small-window custom rule set (MaxWindow = 14, so
// ChunkSize can be the 4096 floor) covering the interesting shapes:
//   - two rules sharing the literal trigger "KEY(" with different windows,
//     confidences, and span lengths (overlapping spans merge);
//   - a case-folded trigger with lookbehind.
func boundaryConfig() Config {
	return Config{
		ChunkSize:   4096,
		EnableRules: []string{"github-pat", "slack-bot-token"},
		CustomRules: []CustomRule{
			{
				ID:           "key-alnum",
				Triggers:     []string{"KEY("},
				Confidence:   ConfidenceHigh,
				MaxLookahead: 10,
				// KEY( + exactly 8 alnum + ')'.
				Validate: func(w []byte, ts, te int) (int, int, bool) {
					if te+9 > len(w) {
						return 0, 0, false
					}
					for i := te; i < te+8; i++ {
						if !isASCIIAlnum(w[i]) {
							return 0, 0, false
						}
					}
					if w[te+8] != ')' {
						return 0, 0, false
					}
					return ts, te + 9, true
				},
			},
			{
				ID:           "key-short",
				Triggers:     []string{"KEY("},
				Confidence:   ConfidenceMedium,
				MaxLookahead: 4,
				// KEY( + at least 4 alnum; redacts trigger + 4.
				Validate: func(w []byte, ts, te int) (int, int, bool) {
					if te+4 > len(w) {
						return 0, 0, false
					}
					for i := te; i < te+4; i++ {
						if !isASCIIAlnum(w[i]) {
							return 0, 0, false
						}
					}
					return ts, te + 4, true
				},
			},
			{
				ID:            "tok",
				Triggers:      []string{"TOK-"},
				CaseFold:      true,
				Confidence:    ConfidenceMedium,
				MaxLookbehind: 2,
				MaxLookahead:  8,
				// tok- + exactly 6 alnum, not preceded by an alnum byte.
				Validate: func(w []byte, ts, te int) (int, int, bool) {
					if ts > 0 && isASCIIAlnum(w[ts-1]) {
						return 0, 0, false
					}
					if te+6 > len(w) {
						return 0, 0, false
					}
					for i := te; i < te+6; i++ {
						if !isASCIIAlnum(w[i]) {
							return 0, 0, false
						}
					}
					if te+6 < len(w) && isASCIIAlnum(w[te+6]) {
						return 0, 0, false
					}
					return ts, te + 6, true
				},
			},
		},
	}
}

// boundaryFixture builds an input a bit over two 4096-byte buffers with
// secrets at offset 0, straddling both internal buffer boundaries,
// adjacent secrets (which merge), shared-trigger and case-folded matches,
// negative cases, and a secret ending exactly at EOF.
func boundaryFixture() []byte {
	var b bytes.Buffer
	b.WriteString("KEY(abcd1234)") // offset 0; key-alnum and key-short overlap -> one merged finding
	b.WriteString(" tok-AbC123 ")  // case-folded trigger, lowercase form
	filler := "log line padding without any trigger material at all.\n"
	for b.Len() < 4090 {
		b.WriteString(filler)
	}
	b.WriteString("KEY(1234wxyz)")              // straddles the first 4096 boundary
	b.WriteString(" TOK-xyz789 ")               // case-folded trigger, uppercase form
	b.WriteString("xtok-aaa111 ")               // rejected: preceded by an alnum byte
	b.WriteString("KEY(zz99!) ")                // key-short only (key-alnum needs 8 alnum + ')')
	b.WriteString("KEY(abcd1234)KEY(zzzz9999)") // adjacent secrets -> merge into one finding
	for b.Len() < 8190 {
		b.WriteString(filler)
	}
	b.WriteString("KEY(9876zyxw)") // straddles the second 4096 boundary
	b.WriteString(" trailing text and then a secret flush against EOF: ")
	b.WriteString("KEY(wxyz6789)") // ends exactly at EOF
	return b.Bytes()
}

// oneShotOracle runs the engine over the input in a single pass, recording
// findings, and cross-checks the output against a splice reconstruction.
func oneShotOracle(t *testing.T, cfg Config, input []byte) (string, Stats, []Finding) {
	t.Helper()
	var findings []Finding
	cfg.OnFinding = func(f Finding) { findings = append(findings, f) }
	e := mustEngine(t, cfg)
	out, stats := redactAll(t, e, bytes.NewReader(input))

	marker := cfg.Marker
	if marker == "" {
		marker = DefaultMarker
	}
	var last int64 = -1
	for _, f := range findings {
		if f.Start < 0 || f.End > int64(len(input)) || f.Start >= f.End || f.Start < last {
			t.Fatalf("finding %+v out of order or out of range", f)
		}
		last = f.End
	}
	if want := spliceExpected(input, findings, marker); out != want {
		t.Fatalf("one-shot output does not equal input spliced with findings\n got: %q\nwant: %q", out, want)
	}
	if stats.Findings != int64(len(findings)) {
		t.Fatalf("Stats.Findings = %d, OnFinding count = %d", stats.Findings, len(findings))
	}
	return out, stats, findings
}

func TestBoundaryFixtureOneShot(t *testing.T) {
	input := boundaryFixture()
	out, stats, _ := oneShotOracle(t, boundaryConfig(), input)

	// Hand-checked aggregates for the fixture: key-alnum wins the merged
	// span at offset 0, both buffer straddlers, the merged adjacent pair,
	// and the EOF secret (5); key-short alone confirms "KEY(zz99!)"; tok
	// confirms both case variants.
	if stats.Findings != 8 {
		t.Errorf("Findings = %d, want 8", stats.Findings)
	}
	want := map[string]int64{"key-alnum": 5, "key-short": 1, "tok": 2}
	for id, n := range want {
		if stats.ByRule[id] != n {
			t.Errorf("ByRule[%q] = %d, want %d", id, stats.ByRule[id], n)
		}
	}
	if len(stats.ByRule) != len(want) {
		t.Errorf("ByRule = %v, want exactly %v", stats.ByRule, want)
	}
	if strings.Contains(out, "KEY(abcd1234)") || strings.Contains(out, "tok-AbC123") {
		t.Error("confirmed secret bytes appear in the output")
	}
	if !strings.Contains(out, "xtok-aaa111") {
		t.Error("rejected candidate was redacted")
	}
	// Adjacent secrets merged: exactly one marker replaces both.
	if strings.Contains(out, "[REDACTED][REDACTED]") {
		t.Error("adjacent spans were not merged into a single marker")
	}
	if !strings.HasSuffix(out, "[REDACTED]") {
		t.Error("secret ending at EOF was not redacted")
	}
	if !strings.HasPrefix(out, "[REDACTED] [REDACTED] ") {
		t.Errorf("secrets at the start were not redacted: %q", out[:24])
	}
}

// TestEveryBoundaryCustom scans the fixture split into two pieces at every
// possible position; every run must match the one-shot output exactly.
func TestEveryBoundaryCustom(t *testing.T) {
	input := boundaryFixture()
	cfg := boundaryConfig()
	want, _, _ := oneShotOracle(t, cfg, input)
	e := mustEngine(t, cfg)

	var out bytes.Buffer
	for split := 0; split <= len(input); split++ {
		out.Reset()
		r := io.MultiReader(bytes.NewReader(input[:split]), bytes.NewReader(input[split:]))
		if _, err := e.Redact(context.Background(), &out, r); err != nil {
			t.Fatalf("split %d: Redact: %v", split, err)
		}
		if out.String() != want {
			t.Fatalf("split %d: output differs from one-shot scan", split)
		}
	}
}

// TestEveryBoundaryBuiltins does the same for the built-in seed rules with
// secrets at offset 0, adjacent to each other, and ending at EOF.
func TestEveryBoundaryBuiltins(t *testing.T) {
	input := []byte(testGHToken + " middle " + testSlackToken + "," + testGHToken2 +
		" noise ghp_tooShort xoxb-1-2-3 tail " + testGHToken)
	want, stats, _ := oneShotOracle(t, Config{}, input)
	if stats.Findings != 4 {
		t.Fatalf("fixture sanity: Findings = %d, want 4", stats.Findings)
	}
	e := mustEngine(t, Config{})

	var out bytes.Buffer
	for split := 0; split <= len(input); split++ {
		out.Reset()
		r := io.MultiReader(bytes.NewReader(input[:split]), bytes.NewReader(input[split:]))
		if _, err := e.Redact(context.Background(), &out, r); err != nil {
			t.Fatalf("split %d: Redact: %v", split, err)
		}
		if out.String() != want {
			t.Fatalf("split %d: output differs from one-shot scan", split)
		}
	}
}

// TestRandomPieceSizes feeds the fixture in seeded random 1..7-byte reads.
func TestRandomPieceSizes(t *testing.T) {
	input := boundaryFixture()
	cfg := boundaryConfig()
	want, _, _ := oneShotOracle(t, cfg, input)
	e := mustEngine(t, cfg)

	var out bytes.Buffer
	for seed := int64(0); seed < 60; seed++ {
		rng := rand.New(rand.NewSource(seed))
		out.Reset()
		r := &chunkedReader{data: input, sizes: func(int) int { return 1 + rng.Intn(7) }}
		if _, err := e.Redact(context.Background(), &out, r); err != nil {
			t.Fatalf("seed %d: Redact: %v", seed, err)
		}
		if out.String() != want {
			t.Fatalf("seed %d: output differs from one-shot scan", seed)
		}
	}
}

// TestChunkedEquivalenceProperty is a seeded property test: random inputs
// salted with trigger fragments and whole secrets must scan identically
// one-shot and randomly chunked, and equal the splice reconstruction.
func TestChunkedEquivalenceProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	salts := []string{
		"ghp_", "xoxb-", testGHToken, testGHToken2, testSlackToken,
		"ghp_" + strings.Repeat("Q", 36), // rejected: placeholder heuristic (all-same body)
		"xoxb-123-456-abc",               // rejected: segments too short
		"\n", " ", "=", "ghp", "xoxb-1234567890-",
	}
	e := mustEngine(t, Config{ChunkSize: 4096, EnableRules: []string{"github-pat", "slack-bot-token"}})

	var in bytes.Buffer
	var out1, out2 bytes.Buffer
	for iter := 0; iter < 120; iter++ {
		in.Reset()
		for in.Len() < 2048+rng.Intn(6144) {
			switch rng.Intn(4) {
			case 0:
				in.WriteString(salts[rng.Intn(len(salts))])
			default:
				n := 1 + rng.Intn(40)
				for i := 0; i < n; i++ {
					in.WriteByte(byte(' ' + rng.Intn(95)))
				}
			}
		}
		input := in.Bytes()

		out1.Reset()
		if _, err := e.Redact(context.Background(), &out1, bytes.NewReader(input)); err != nil {
			t.Fatalf("iter %d: one-shot Redact: %v", iter, err)
		}
		out2.Reset()
		pieceCap := 1 + rng.Intn(97)
		r := &chunkedReader{data: input, sizes: func(int) int { return 1 + rng.Intn(pieceCap) }}
		if _, err := e.Redact(context.Background(), &out2, r); err != nil {
			t.Fatalf("iter %d: chunked Redact: %v", iter, err)
		}
		if !bytes.Equal(out1.Bytes(), out2.Bytes()) {
			t.Fatalf("iter %d: chunked output differs from one-shot", iter)
		}

		// Cross-check against the splice oracle (fresh engine to capture
		// findings for this input).
		var findings []Finding
		eo := mustEngine(t, Config{ChunkSize: 4096, EnableRules: []string{"github-pat", "slack-bot-token"}, OnFinding: func(f Finding) { findings = append(findings, f) }})
		var out3 bytes.Buffer
		if _, err := eo.Redact(context.Background(), &out3, bytes.NewReader(input)); err != nil {
			t.Fatalf("iter %d: oracle Redact: %v", iter, err)
		}
		if want := spliceExpected(input, findings, DefaultMarker); out3.String() != want {
			t.Fatalf("iter %d: output does not equal splice reconstruction", iter)
		}
		if !bytes.Equal(out1.Bytes(), out3.Bytes()) {
			t.Fatalf("iter %d: engines disagree", iter)
		}
	}
}
