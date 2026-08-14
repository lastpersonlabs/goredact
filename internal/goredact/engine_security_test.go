package goredact

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

type repeatedByteReader struct {
	remaining int64
	maxRead   int
}

func (r *repeatedByteReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = byte(0x80 + i%64) // arbitrary invalid UTF-8, no ASCII triggers
	}
	r.remaining -= int64(n)
	return n, nil
}

func TestHugeArbitraryInputUsesBoundedReads(t *testing.T) {
	const (
		chunk = 4096
		size  = 32 << 20
	)
	e := mustEngine(t, Config{ChunkSize: chunk, EnableRules: []string{"github-pat"}})
	src := &repeatedByteReader{remaining: size}
	stats, err := e.Redact(context.Background(), io.Discard, src)
	if err != nil {
		t.Fatal(err)
	}
	if stats.BytesRead != size || stats.BytesWritten != size {
		t.Fatalf("stats=%+v, want %d bytes copied", stats, size)
	}
	if src.maxRead > chunk {
		t.Fatalf("largest read request = %d, exceeds fixed chunk %d", src.maxRead, chunk)
	}
}

type invalidCountReader struct{ fragment []byte }

func (r invalidCountReader) Read(p []byte) (int, error) {
	copy(p, r.fragment)
	return len(p) + 1, nil
}

func TestInternalReadErrorsNeverIncludeInputFragments(t *testing.T) {
	const secret = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	e := mustEngine(t, Config{ChunkSize: 4096, EnableRules: []string{"github-pat"}})
	var out bytes.Buffer
	_, err := e.Redact(context.Background(), &out, invalidCountReader{fragment: []byte(secret)})
	if err == nil {
		t.Fatal("expected invalid-read-count error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "ghp_") {
		t.Fatalf("internal error leaked source fragment: %q", err)
	}
	if out.Len() != 0 {
		t.Fatalf("invalid reader produced output %q", out.Bytes())
	}
}
