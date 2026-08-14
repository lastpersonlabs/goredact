package goredact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Test fixtures: shape-valid (but fabricated) tokens for the two built-in
// seed rules.
const (
	testGHToken    = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"            // ghp_ + 36 alnum
	testGHToken2   = "ghp_Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9Oo8"            // another one
	testSlackToken = "xoxb-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx" // 10-10-24
)

func mustEngine(t testing.TB, cfg Config) *Engine {
	t.Helper()
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func redactAll(t testing.TB, e *Engine, src io.Reader) (string, Stats) {
	t.Helper()
	var out bytes.Buffer
	stats, err := e.Redact(context.Background(), &out, src)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	return out.String(), stats
}

// chunkedReader yields data in pieces whose sizes are produced by sizes
// (called with the 0-based read index); pieces are clamped to [1, len(p)]
// and to the remaining data.
type chunkedReader struct {
	data  []byte
	sizes func(i int) int
	off   int
	i     int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := r.sizes(r.i)
	r.i++
	if n < 1 {
		n = 1
	}
	if n > len(p) {
		n = len(p)
	}
	if rem := len(r.data) - r.off; n > rem {
		n = rem
	}
	copy(p, r.data[r.off:r.off+n])
	r.off += n
	return n, nil
}

// spliceExpected rebuilds the expected redacted output from the input and
// the (merged, sorted, non-overlapping) findings reported by OnFinding.
func spliceExpected(input []byte, findings []Finding, marker string) string {
	var b strings.Builder
	var pos int64
	for _, f := range findings {
		b.Write(input[pos:f.Start])
		b.WriteString(marker)
		pos = f.End
	}
	b.Write(input[pos:])
	return b.String()
}

func TestRedactBuiltinsEndToEnd(t *testing.T) {
	var findings []Finding
	e := mustEngine(t, Config{OnFinding: func(f Finding) { findings = append(findings, f) }})

	in := "before " + testGHToken + " middle " + testSlackToken + "\nafter"
	want := "before [REDACTED] middle [REDACTED]\nafter"

	out, stats := redactAll(t, e, strings.NewReader(in))
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
	if stats.BytesRead != int64(len(in)) {
		t.Errorf("BytesRead = %d, want %d", stats.BytesRead, len(in))
	}
	if stats.BytesWritten != int64(len(want)) {
		t.Errorf("BytesWritten = %d, want %d", stats.BytesWritten, len(want))
	}
	if wantRedacted := int64(len(testGHToken) + len(testSlackToken)); stats.RedactedBytes != wantRedacted {
		t.Errorf("RedactedBytes = %d, want %d", stats.RedactedBytes, wantRedacted)
	}
	if stats.Findings != 2 {
		t.Errorf("Findings = %d, want 2", stats.Findings)
	}
	if stats.ByRule["github-pat"] != 1 || stats.ByRule["slack-bot-token"] != 1 || len(stats.ByRule) != 2 {
		t.Errorf("ByRule = %v", stats.ByRule)
	}

	if len(findings) != 2 {
		t.Fatalf("OnFinding invocations = %d, want 2", len(findings))
	}
	ghStart := int64(len("before "))
	if f := findings[0]; f.RuleID != "github-pat" || f.Confidence != ConfidenceHigh ||
		f.Start != ghStart || f.End != ghStart+int64(len(testGHToken)) {
		t.Errorf("findings[0] = %+v", f)
	}
	slackStart := ghStart + int64(len(testGHToken)) + int64(len(" middle "))
	if f := findings[1]; f.RuleID != "slack-bot-token" || f.Confidence != ConfidenceHigh ||
		f.Start != slackStart || f.End != slackStart+int64(len(testSlackToken)) {
		t.Errorf("findings[1] = %+v", f)
	}
}

func TestRedactCustomMarker(t *testing.T) {
	e := mustEngine(t, Config{Marker: "<CUT>"})
	in := "x " + testGHToken + " y"
	out, _ := redactAll(t, e, strings.NewReader(in))
	if want := "x <CUT> y"; out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestRedactNoMatches(t *testing.T) {
	e := mustEngine(t, Config{})
	in := strings.Repeat("nothing secret here, just plain logs\n", 300)
	out, stats := redactAll(t, e, strings.NewReader(in))
	if out != in {
		t.Fatal("match-free input was altered")
	}
	if stats.Findings != 0 || stats.RedactedBytes != 0 {
		t.Errorf("stats = %+v, want no findings", stats)
	}
	if stats.ByRule != nil {
		t.Errorf("ByRule = %v, want nil when there are no findings", stats.ByRule)
	}
	if stats.BytesRead != int64(len(in)) || stats.BytesWritten != int64(len(in)) {
		t.Errorf("BytesRead/BytesWritten = %d/%d, want %d", stats.BytesRead, stats.BytesWritten, len(in))
	}
}

func TestRedactSmallInputs(t *testing.T) {
	e := mustEngine(t, Config{})
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"single byte", "a", "a"},
		{"bare trigger", "ghp_", "ghp_"},
		{"trigger with short tail", "ghp_abc", "ghp_abc"},
		{"truncated candidate at EOF", "data ghp_A1b2C3", "data ghp_A1b2C3"},
		{"secret is the whole input", testGHToken, "[REDACTED]"},
		{"smaller than one window", "tiny xoxb-1-2 tail", "tiny xoxb-1-2 tail"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, stats := redactAll(t, e, strings.NewReader(tc.in))
			if out != tc.want {
				t.Fatalf("output = %q, want %q", out, tc.want)
			}
			if stats.BytesRead != int64(len(tc.in)) {
				t.Errorf("BytesRead = %d, want %d", stats.BytesRead, len(tc.in))
			}
		})
	}
}

func TestRedactEmptyRuleSet(t *testing.T) {
	e := mustEngine(t, Config{DisableRules: []string{"github-pat", "slack-bot-token"}})
	in := "even a real-looking " + testGHToken + " passes through with no rules"
	out, stats := redactAll(t, e, strings.NewReader(in))
	if out != in {
		t.Fatalf("output = %q, want the input unchanged", out)
	}
	if stats.Findings != 0 || stats.ByRule != nil {
		t.Errorf("stats = %+v, want zero findings", stats)
	}
}

func TestRedactCaseFoldedCustomTrigger(t *testing.T) {
	e := mustEngine(t, Config{CustomRules: []CustomRule{{
		ID:           "shout",
		Triggers:     []string{"SeCrEt="},
		CaseFold:     true,
		Confidence:   ConfidenceMedium,
		MaxLookahead: 8,
		Validate: func(w []byte, ts, te int) (int, int, bool) {
			end := te
			for end < len(w) && w[end] != ' ' && w[end] != '\n' {
				end++
			}
			if end == te {
				return 0, 0, false
			}
			return ts, end, true
		},
	}}})
	in := "a SECRET=abc b secret=xyz c SeCrEt=123 d"
	want := "a [REDACTED] b [REDACTED] c [REDACTED] d"
	out, stats := redactAll(t, e, strings.NewReader(in))
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
	if stats.ByRule["shout"] != 3 {
		t.Errorf("ByRule = %v, want shout:3", stats.ByRule)
	}
}

func TestRedactContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// An endless reader that cancels the context after a few reads and
	// keeps supplying secret-bearing data forever after.
	block := []byte("log line with token " + testGHToken + " inside\n")
	reads := 0
	r := readerFunc(func(p []byte) (int, error) {
		reads++
		if reads == 3 {
			cancel()
		}
		n := 0
		for n+len(block) <= len(p) {
			n += copy(p[n:], block)
		}
		if n == 0 {
			n = copy(p, block)
		}
		return n, nil
	})

	e := mustEngine(t, Config{})
	var out bytes.Buffer
	stats, err := e.Redact(ctx, &out, r)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if err != context.Canceled {
		t.Fatalf("ctx.Err() must be returned unwrapped, got %T: %v", err, err)
	}
	if reads > 10 {
		t.Errorf("cancellation was not prompt: %d reads", reads)
	}
	if bytes.Contains(out.Bytes(), []byte(testGHToken)) {
		t.Error("cancelled scan emitted an unredacted confirmed secret")
	}
	if stats.BytesWritten != int64(out.Len()) {
		t.Errorf("partial BytesWritten = %d, want %d", stats.BytesWritten, out.Len())
	}
}

type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestRedactReadError(t *testing.T) {
	errBoom := errors.New("boom")
	data := []byte("head " + testGHToken + " tail that keeps going for a while")
	served := false
	r := readerFunc(func(p []byte) (int, error) {
		if served {
			return 0, errBoom
		}
		served = true
		return copy(p, data), nil
	})

	e := mustEngine(t, Config{})
	var out bytes.Buffer
	stats, err := e.Redact(context.Background(), &out, r)

	var re *ReadError
	if !errors.As(err, &re) {
		t.Fatalf("err = %T (%v), want *ReadError", err, err)
	}
	if !errors.Is(err, errBoom) {
		t.Errorf("ReadError does not unwrap to the reader's error: %v", err)
	}
	if stats.BytesRead != int64(len(data)) {
		t.Errorf("partial BytesRead = %d, want %d", stats.BytesRead, len(data))
	}
	if bytes.Contains(out.Bytes(), []byte(testGHToken)) {
		t.Error("partial output contains an unredacted confirmed secret")
	}
	// Whatever was flushed must be a prefix of the full redacted output.
	full, _ := redactAll(t, e, bytes.NewReader(data))
	if !strings.HasPrefix(full, out.String()) {
		t.Errorf("partial output %q is not a prefix of full output %q", out.String(), full)
	}
}

// failAfterWriter fails with err once more than limit bytes have been
// attempted.
type failAfterWriter struct {
	limit   int
	written int
	err     error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.limit {
		n := w.limit - w.written
		if n < 0 {
			n = 0
		}
		w.written += n
		return n, w.err
	}
	w.written += len(p)
	return len(p), nil
}

func TestRedactWriteError(t *testing.T) {
	errBoom := errors.New("disk full")
	e := mustEngine(t, Config{})
	in := "prefix " + testGHToken + " " + strings.Repeat("filler\n", 40)

	w := &failAfterWriter{limit: 20, err: errBoom}
	stats, err := e.Redact(context.Background(), w, strings.NewReader(in))

	var we *WriteError
	if !errors.As(err, &we) {
		t.Fatalf("err = %T (%v), want *WriteError", err, err)
	}
	if !errors.Is(err, errBoom) {
		t.Errorf("WriteError does not unwrap to the writer's error: %v", err)
	}
	if stats.BytesWritten != int64(w.written) {
		t.Errorf("partial BytesWritten = %d, want %d", stats.BytesWritten, w.written)
	}
}

func TestRedactZeroReadReader(t *testing.T) {
	e := mustEngine(t, Config{})
	r := readerFunc(func(p []byte) (int, error) { return 0, nil })
	_, err := e.Redact(context.Background(), io.Discard, r)
	var re *ReadError
	if !errors.As(err, &re) || !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("err = %v, want *ReadError wrapping io.ErrNoProgress", err)
	}
}

func TestRedactConcurrent(t *testing.T) {
	e := mustEngine(t, Config{ChunkSize: 4096, EnableRules: []string{"github-pat", "slack-bot-token"}})

	// A few distinct inputs with known outputs, scanned concurrently on
	// the one shared Engine.
	inputs := make([]string, 4)
	wants := make([]string, 4)
	for i := range inputs {
		var in strings.Builder
		for j := 0; j < 200; j++ {
			fmt.Fprintf(&in, "worker %d line %d\n", i, j)
			if j%17 == i {
				in.WriteString(testGHToken + "\n")
			}
			if j%23 == i {
				in.WriteString(testSlackToken + "\n")
			}
		}
		inputs[i] = in.String()
		wants[i], _ = redactAll(t, e, strings.NewReader(inputs[i]))
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for iter := 0; iter < 10; iter++ {
				i := (g + iter) % len(inputs)
				var out bytes.Buffer
				_, err := e.Redact(context.Background(), &out, strings.NewReader(inputs[i]))
				if err != nil {
					t.Errorf("goroutine %d: Redact: %v", g, err)
					return
				}
				if out.String() != wants[i] {
					t.Errorf("goroutine %d: output mismatch on input %d", g, i)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestRedactMergedChainLongerThanBuffer exercises the buffer-pressure path:
// a custom rule whose confirmed spans are adjacent merges into one span far
// longer than the chunk buffer, forcing the engine to discard span-interior
// bytes and later emit the region via zero-filled scratch — while producing
// exactly one marker and one finding, byte-identical to a logical one-shot.
func TestRedactMergedChainLongerThanBuffer(t *testing.T) {
	cfg := Config{
		ChunkSize:   4096,
		EnableRules: []string{"github-pat", "slack-bot-token"},
		CustomRules: []CustomRule{{
			ID:         "chain",
			Triggers:   []string{"ab"},
			Confidence: ConfidenceMedium,
			Validate: func(w []byte, ts, te int) (int, int, bool) {
				return ts, te, true
			},
		}},
	}
	e := mustEngine(t, cfg)

	const pairs = 60000 // 120000 chained bytes, ~30 buffers long
	in := "xx" + strings.Repeat("ab", pairs) + "!tail " + testGHToken + " end"
	want := "xx[REDACTED]!tail [REDACTED] end"

	out, stats := redactAll(t, e, strings.NewReader(in))
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
	if stats.Findings != 2 {
		t.Errorf("Findings = %d, want 2 (one merged chain, one token)", stats.Findings)
	}
	if stats.ByRule["chain"] != 1 || stats.ByRule["github-pat"] != 1 {
		t.Errorf("ByRule = %v", stats.ByRule)
	}
	if wantRedacted := int64(2*pairs + len(testGHToken)); stats.RedactedBytes != wantRedacted {
		t.Errorf("RedactedBytes = %d, want %d", stats.RedactedBytes, wantRedacted)
	}

	// Same input delivered in awkward piece sizes must be identical.
	rng := rand.New(rand.NewSource(7))
	chunked := &chunkedReader{data: []byte(in), sizes: func(int) int { return 1 + rng.Intn(64) }}
	out2, _ := redactAll(t, e, chunked)
	if out2 != want {
		t.Fatalf("chunked chain output = %q, want %q", out2, want)
	}
}

// recordingWriter captures the cumulative output length after every Write,
// to observe the engine's emission boundaries.
type recordingWriter struct {
	buf    bytes.Buffer
	bounds []int
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	n, err := w.buf.Write(p)
	w.bounds = append(w.bounds, w.buf.Len())
	return n, err
}

// TestRecordAlignedEmission exercises the unexported record-aware hook
// (Engine.recordAligned): mid-stream emission boundaries must land just
// past a '\n' whenever one is buffered, and the hook must fall back to raw
// limits (no deadlock, identical output) when the input has no newlines.
// ENG-99's escaped-JSON record detection builds on this hook.
func TestRecordAlignedEmission(t *testing.T) {
	line := strings.Repeat("x", 39) + "\n"
	in := strings.Repeat(line, 512) // 20480 bytes, several 4096 buffers

	e := mustEngine(t, Config{ChunkSize: 4096, EnableRules: []string{"github-pat", "slack-bot-token"}})
	e.recordAligned = true // internal test hook; public knob lands with ENG-99/ENG-101

	w := &recordingWriter{}
	stats, err := e.Redact(context.Background(), w,
		&chunkedReader{data: []byte(in), sizes: func(int) int { return 1000 }})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if w.buf.String() != in {
		t.Fatal("record-aligned output differs from input")
	}
	if stats.BytesWritten != int64(len(in)) {
		t.Errorf("BytesWritten = %d, want %d", stats.BytesWritten, len(in))
	}
	if len(w.bounds) < 2 {
		t.Fatalf("expected multiple emissions, got bounds %v", w.bounds)
	}
	out := w.buf.Bytes()
	for _, b := range w.bounds[:len(w.bounds)-1] {
		if out[b-1] != '\n' {
			t.Errorf("mid-stream emission boundary at %d does not follow a newline", b)
		}
	}

	// Newline-free input: alignment must fall back to raw limits and
	// still drain the stream completely.
	flat := strings.Repeat("y", 20480)
	var out2 bytes.Buffer
	_, err = e.Redact(context.Background(), &out2,
		&chunkedReader{data: []byte(flat), sizes: func(int) int { return 1000 }})
	if err != nil {
		t.Fatalf("Redact (no newlines): %v", err)
	}
	if out2.String() != flat {
		t.Fatal("newline-free record-aligned output differs from input")
	}
}

// TestRedactBoundedMemory scans a 1 GiB synthetic stream through the
// engine and asserts the heap grows by no more than a few MiB. The engine
// never opens files — input flows reader -> fixed buffer -> writer only
// (enforced by code inspection: engine.go imports no filesystem APIs).
func TestRedactBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("1 GiB stream scan skipped in -short mode")
	}

	// 64 KiB block with one secret; 16384 repeats = 1 GiB exactly.
	const blockSize = 64 * 1024
	const total = int64(1) << 30
	filler := []byte("2026-08-14T12:00:00Z info request handled in 3ms status=200 path=/api/v1/items\n")
	block := make([]byte, 0, blockSize)
	block = append(block, "token "+testGHToken+"\n"...)
	for len(block)+len(filler) <= blockSize {
		block = append(block, filler...)
	}
	block = append(block, bytes.Repeat([]byte{'.'}, blockSize-len(block))...)

	e := mustEngine(t, Config{})
	// Warm-up run so pooled buffers and lazy allocations exist before the
	// baseline measurement.
	if _, err := e.Redact(context.Background(), io.Discard, &repeatReader{block: block, total: 4 * blockSize}); err != nil {
		t.Fatalf("warm-up Redact: %v", err)
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	stats, err := e.Redact(context.Background(), io.Discard, &repeatReader{block: block, total: total})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if stats.BytesRead != total {
		t.Errorf("BytesRead = %d, want %d", stats.BytesRead, total)
	}
	wantFindings := int(total / blockSize)
	if stats.Findings != wantFindings {
		t.Errorf("Findings = %d, want %d", stats.Findings, wantFindings)
	}
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if delta > 8<<20 {
		t.Errorf("HeapAlloc grew by %d bytes scanning 1 GiB; want <= 8 MiB", delta)
	}
}

// repeatReader serves `total` bytes by cycling over block.
type repeatReader struct {
	block []byte
	total int64
	off   int64
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.off >= r.total {
		return 0, io.EOF
	}
	if rem := r.total - r.off; int64(len(p)) > rem {
		p = p[:rem]
	}
	n := copy(p, r.block[r.off%int64(len(r.block)):])
	r.off += int64(n)
	return n, nil
}
