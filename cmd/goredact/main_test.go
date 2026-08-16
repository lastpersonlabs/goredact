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

func TestSameFileNameAliasing(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	other := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(in, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !sameFileName(in, in) {
		t.Fatal("identical paths should be detected as the same file")
	}
	if sameFileName(in, other) {
		t.Fatal("distinct, non-existent output should not alias the input")
	}

	symlink := filepath.Join(dir, "sym.txt")
	if err := os.Symlink(in, symlink); err != nil {
		t.Fatal(err)
	}
	if !sameFileName(in, symlink) {
		t.Fatal("symlink to input should alias the input")
	}

	hardlink := filepath.Join(dir, "hard.txt")
	if err := os.Link(in, hardlink); err != nil {
		t.Skipf("hardlinks unsupported on this platform: %v", err)
	}
	if !sameFileName(in, hardlink) {
		t.Fatal("hardlink to input should alias the input")
	}
}

func TestRunStreamRefusesSymlinkAliasedOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	secret := "AWS_SECRET_ACCESS_KEY=fKm/r5kJP1VrT+1FJors/6ILi8IHn5kxsC7tVO/H\n"
	if err := os.WriteFile(in, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out-link")
	if err := os.Symlink(in, link); err != nil {
		t.Fatal(err)
	}

	err := run(context.Background(), []string{"stream", "-input=" + in, "-output=" + link}, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected an error for symlink-aliased output")
	}
	got, readErr := os.ReadFile(in)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != secret {
		t.Fatalf("input was modified: got %q", got)
	}
}

// TestRunHelpFlagIsNotAFailure pins Cobra's standard help behavior: help is
// successful, is written to stdout, and does not pollute stderr.
func TestRunHelpFlagIsNotAFailure(t *testing.T) {
	for _, args := range [][]string{{"stream", "-h"}, {"stream", "-help"}, {"dir", "-h"}, {"dir", "-help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			err := run(context.Background(), args, nil, &output, &diagnostics)
			if err != nil {
				t.Fatalf("run(%v) error = %v, want nil", args, err)
			}
			if !strings.Contains(output.String(), "Usage:") || diagnostics.Len() != 0 {
				t.Fatalf("stdout = %q, stderr = %q", output.String(), diagnostics.String())
			}
		})
	}
}

func TestRootHelpVersionAndCommandSuggestions(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, nil, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Available Commands:", "completion", "stream", "dir"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("root help omitted %q: %q", want, output.String())
		}
	}

	output.Reset()
	if err := run(context.Background(), []string{"--version"}, nil, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "goredact version ") {
		t.Fatalf("version output = %q", output.String())
	}

	err := run(context.Background(), []string{"streem"}, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "stream") {
		t.Fatalf("unknown-command error = %v, want stream suggestion", err)
	}
}

func TestRunSupportsConventionalShorthandFlags(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"stream", "-p", "fast", "-m", "fixed-marker"}, strings.NewReader("ordinary text"), &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if output.String() != "ordinary text" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestInvocationErrorsShowRelevantUsage(t *testing.T) {
	var diagnostics bytes.Buffer
	err := run(context.Background(), []string{"dir"}, nil, io.Discard, &diagnostics)
	if err == nil {
		t.Fatal("missing path succeeded")
	}
	if !strings.Contains(diagnostics.String(), "Usage:\n  goredact dir [flags] <path>") {
		t.Fatalf("diagnostics = %q, want dir usage", diagnostics.String())
	}

	diagnostics.Reset()
	err = run(context.Background(), []string{"stream", "--not-a-flag"}, nil, io.Discard, &diagnostics)
	if err == nil {
		t.Fatal("unknown flag succeeded")
	}
	if !strings.Contains(diagnostics.String(), "Usage:\n  goredact stream [flags]") {
		t.Fatalf("diagnostics = %q, want stream usage", diagnostics.String())
	}
}

func TestOperationalErrorsDoNotShowUsage(t *testing.T) {
	var diagnostics bytes.Buffer
	err := run(context.Background(), []string{"dir", "--exit-code=126", "."}, nil, io.Discard, &diagnostics)
	if err == nil {
		t.Fatal("invalid exit code succeeded")
	}
	if strings.Contains(diagnostics.String(), "Usage:") {
		t.Fatalf("operational error printed usage: %q", diagnostics.String())
	}
}

// TestRunStreamRefusesAliasedStats pins that -stats may name neither the
// input file (writeStats would truncate the file being scanned) nor the
// output file (it would clobber the just-written redacted result).
func TestRunStreamRefusesAliasedStats(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	out := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(in, []byte("ordinary text"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, stats := range []string{in, out} {
		err := run(context.Background(), []string{"stream", "-input=" + in, "-output=" + out, "-stats=" + stats}, nil, io.Discard, io.Discard)
		if err == nil {
			t.Fatalf("-stats=%s: expected an aliasing error", stats)
		}
	}
	if got, err := os.ReadFile(in); err != nil || string(got) != "ordinary text" {
		t.Fatalf("input was modified: %q, %v", got, err)
	}
}

// TestRunStreamFailureEmptiesSymlinkTarget pins the failure cleanup for a
// symlinked -output pointing at an unrelated file: the target must not be
// left holding partial output (it is truncated before the link is
// removed).
func TestRunStreamFailureEmptiesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.dat")
	if err := os.WriteFile(target, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), []string{"stream", "-output=" + link}, &failingReader{err: errors.New("boom")}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected a scan failure")
	}
	if _, statErr := os.Lstat(link); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("output link remains: %v", statErr)
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(got) != 0 {
		t.Fatalf("symlink target holds %q, want empty after failure cleanup", got)
	}
}

// TestRunFailedStatsWriteKeepsOutput pins that a stats-sidecar write
// failure reports an error but does not delete the already-complete,
// correctly redacted output file.
func TestRunFailedStatsWriteKeepsOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input")
	out := filepath.Join(dir, "output")
	if err := os.WriteFile(in, []byte("ordinary text"), 0o600); err != nil {
		t.Fatal(err)
	}
	badStatsPath := filepath.Join(dir, "nonexistent-subdir", "stats.json")

	err := run(context.Background(), []string{"stream", "-input=" + in, "-output=" + out, "-stats=" + badStatsPath}, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected a stats-write error")
	}
	got, readErr := os.ReadFile(out)
	if readErr != nil {
		t.Fatalf("completed output was removed: %v", readErr)
	}
	if string(got) != "ordinary text" {
		t.Fatalf("output = %q, want the redacted content preserved", got)
	}
}
