package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestRunStdinStdoutProgressAndStats(t *testing.T) {
	input := "before AWS_ACCESS_KEY_ID=AKIAUJZDEGXDNCF32EPF after"
	var output, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"stream", "-profile=fast", "-progress-bytes=1", "-stats=-"}, strings.NewReader(input), &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "AKIAUJZDEGXDNCF32EPF") || !strings.Contains(output.String(), "[REDACTED]") {
		t.Fatalf("unexpected output %q", output.String())
	}
	if strings.Contains(diagnostics.String(), "AKIAUJZDEGXDNCF32EPF") {
		t.Fatal("diagnostics leaked matched content")
	}
	lines := strings.Split(strings.TrimSpace(diagnostics.String()), "\n")
	var stats map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &stats); err != nil {
		t.Fatalf("last diagnostic is not JSON: %v", err)
	}
}

func TestRunStreamsZstandard(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"stream", "-zstd"}, strings.NewReader("hello"), &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	decoder, err := zstd.NewReader(&output, zstd.WithDecoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	got, err := io.ReadAll(decoder)
	if err != nil || string(got) != "hello" {
		t.Fatalf("decoded = %q, %v", got, err)
	}
}

func TestRunFilesAndFailedScanRemovesOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input")
	out := filepath.Join(dir, "output")
	if err := os.WriteFile(in, []byte("ordinary text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"stream", "-input=" + in, "-output=" + out}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(out); err != nil || string(got) != "ordinary text" {
		t.Fatalf("output = %q, %v", got, err)
	}

	secret := "AKIAUJZDEGXDNCF32EPF"
	err := run(context.Background(), []string{"stream", "-output=" + out}, &failingReader{err: errors.New(secret)}, io.Discard, io.Discard)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error: %v", err)
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial output remains: %v", statErr)
	}
}

func TestRunMaskFlag(t *testing.T) {
	input := "before AWS_ACCESS_KEY_ID=AKIAUJZDEGXDNCF32EPF after"

	var output bytes.Buffer
	if err := run(context.Background(), []string{"stream", "-mask=length-preserving"}, strings.NewReader(input), &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if output.Len() != len(input) {
		t.Fatalf("length-preserving output length = %d, want %d", output.Len(), len(input))
	}
	if strings.Contains(output.String(), "AKIAUJZDEGXDNCF32EPF") || !strings.Contains(output.String(), strings.Repeat("*", 20)) {
		t.Fatalf("unexpected output %q", output.String())
	}

	output.Reset()
	if err := run(context.Background(), []string{"stream", "-mask=format-preserving"}, strings.NewReader(input), &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if output.Len() != len(input) || strings.Contains(output.String(), "AKIAUJZDEGXDNCF32EPF") {
		t.Fatalf("unexpected output %q", output.String())
	}

	if err := run(context.Background(), []string{"stream", "-mask=nonsense"}, strings.NewReader(""), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "unknown mask strategy") {
		t.Fatalf("invalid -mask error = %v", err)
	}
}

type failingReader struct{ err error }

func (r *failingReader) Read([]byte) (int, error) { return 0, r.err }
