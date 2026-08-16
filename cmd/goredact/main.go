// Command goredact is a reference streaming integration for the goredact
// library. It never creates plaintext temporary files.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/lastpersonlabs/goredact"
)

type options struct {
	input, output, profile, mask, stats string
	zstd                                bool
	progressEvery                       int64
}

// errUsage marks a flag-parsing failure that flag.Parse has already
// reported to stderr (message plus usage); main must not print it again.
var errUsage = errors.New("goredact: invalid arguments")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// flag.Parse already printed usage to stderr; -h/-help is not
			// a failure and should not also print "flag: help requested".
			os.Exit(0)
		}
		if errors.Is(err, errUsage) {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err)
		var findings findingsError
		if errors.As(err, &findings) {
			os.Exit(findings.code)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("goredact: command required (use stream or dir)")
	}
	switch args[0] {
	case "stream":
		return runStream(ctx, args[1:], stdin, stdout, stderr)
	case "dir":
		return runDir(ctx, args[1:], stdout, stderr)
	default:
		return errors.New("goredact: unknown command (use stream or dir)")
	}
}

func runStream(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("goredact stream", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.input, "input", "-", "input file ('-' for stdin)")
	fs.StringVar(&o.output, "output", "-", "output file ('-' for stdout)")
	fs.StringVar(&o.profile, "profile", "balanced", "detection profile: fast, balanced, or deep")
	fs.StringVar(&o.mask, "mask", "fixed-marker", "mask strategy: fixed-marker, length-preserving, or format-preserving")
	fs.StringVar(&o.stats, "stats", "", "write JSON statistics to this file ('-' for stderr)")
	fs.BoolVar(&o.zstd, "zstd", false, "stream output as a Zstandard frame")
	fs.Int64Var(&o.progressEvery, "progress-bytes", 0, "report bytes read at this interval to stderr (0 disables)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() != 0 {
		return errors.New("goredact: unexpected positional arguments")
	}
	if o.progressEvery < 0 {
		return errors.New("goredact: -progress-bytes must be non-negative")
	}
	if sameFileName(o.input, o.output) {
		return errors.New("goredact: input and output files must differ")
	}
	// -stats must not alias the input (it would clobber the file being
	// scanned) or the output (it would clobber the redacted result).
	if o.stats != "" && o.stats != "-" {
		if sameFileName(o.stats, o.input) || sameFileName(o.stats, o.output) {
			return errors.New("goredact: -stats must differ from input and output files")
		}
	}

	profile, err := parseProfile(o.profile)
	if err != nil {
		return err
	}
	mask, err := parseMask(o.mask)
	if err != nil {
		return err
	}
	engine, err := goredact.New(goredact.Config{Profile: profile, MaskStrategy: mask})
	if err != nil {
		return fmt.Errorf("goredact: configure engine: %w", err)
	}

	src, closeInput, err := openInput(o.input, stdin)
	if err != nil {
		// err is an *os.PathError: operation, user-supplied path, and
		// errno — never scanned content — so surfacing it is safe and
		// tells the user whether the problem is absence or permissions.
		return fmt.Errorf("goredact: cannot open input: %w", err)
	}
	defer closeInput()
	dst, outFile, err := openOutput(o.output, stdout)
	if err != nil {
		return fmt.Errorf("goredact: cannot open output: %w", err)
	}
	succeeded := false
	defer func() {
		if outFile == nil {
			return
		}
		if !succeeded {
			// Empty the file before unlinking the name: when o.output is
			// a symlink, os.Remove only removes the link, so truncating
			// first also honors the "removed on failure" contract for the
			// link's target instead of leaving partial output behind.
			_ = outFile.Truncate(0)
		}
		_ = outFile.Close()
		if !succeeded {
			_ = os.Remove(o.output)
		}
	}()

	reader := io.Reader(src)
	if o.progressEvery > 0 {
		reader = &progressReader{src: src, dst: stderr, every: o.progressEvery, next: o.progressEvery}
	}
	redactedDst := dst
	var compressor *zstd.Encoder
	if o.zstd {
		compressor, err = zstd.NewWriter(dst, zstd.WithEncoderConcurrency(1))
		if err != nil {
			return errors.New("goredact: cannot start compressed output")
		}
		redactedDst = compressor
	}
	stats, err := engine.Redact(ctx, redactedDst, reader)
	if err != nil {
		return safeScanError(err)
	}
	if compressor != nil {
		if err := compressor.Close(); err != nil {
			return errors.New("goredact: cannot finish compressed output")
		}
	}
	// Close the output before declaring success: a deferred write that
	// only fails at close (quota, NFS) must count as a failed scan, not
	// exit 0 with a silently incomplete file. The deferred cleanup treats
	// the already-closed file as failed and removes it.
	if outFile != nil {
		f := outFile
		outFile = nil
		if err := f.Close(); err != nil {
			// Empty the underlying file by path before unlinking the
			// name: when -output is a symlink or hard link, os.Remove
			// only detaches this name, and the closed fd can no longer
			// truncate, so a path-based truncate is what keeps the
			// incomplete result from remaining reachable through the
			// target or another link.
			_ = os.Truncate(o.output, 0)
			_ = os.Remove(o.output)
			return errors.New("goredact: cannot finalize output")
		}
	}
	// The redacted output is already complete and correct at this point:
	// a failure writing the optional stats sidecar below must not delete
	// it, so succeeded is set before attempting that write.
	succeeded = true
	if err := writeStats(o.stats, stats, stderr); err != nil {
		return err
	}
	return nil
}

func parseProfile(s string) (goredact.Profile, error) {
	switch strings.ToLower(s) {
	case "fast":
		return goredact.ProfileFast, nil
	case "balanced":
		return goredact.ProfileBalanced, nil
	case "deep":
		return goredact.ProfileDeep, nil
	default:
		return 0, errors.New("goredact: unknown profile (use fast, balanced, or deep)")
	}
}

func parseMask(s string) (goredact.MaskStrategy, error) {
	switch strings.ToLower(s) {
	case "fixed-marker":
		return goredact.MaskFixedMarker, nil
	case "length-preserving":
		return goredact.MaskLengthPreserving, nil
	case "format-preserving":
		return goredact.MaskFormatPreserving, nil
	default:
		return 0, errors.New("goredact: unknown mask strategy (use fixed-marker, length-preserving, or format-preserving)")
	}
}

func openInput(name string, fallback io.Reader) (io.Reader, func(), error) {
	if name == "-" {
		return fallback, func() {}, nil
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, func() {}, err
	}
	return f, func() { _ = f.Close() }, nil
}

// openOutput opens name for writing, or returns fallback (with a nil
// *os.File) when name is "-". The caller owns closing the returned file.
func openOutput(name string, fallback io.Writer) (io.Writer, *os.File, error) {
	if name == "-" {
		return fallback, nil, nil
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}

func sameFileName(a, b string) bool {
	if a == "-" || b == "-" {
		return false
	}
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA == nil && errB == nil && aa == bb {
		return true
	}
	aInfo, err := os.Stat(a)
	if err != nil {
		return false
	}
	bInfo, err := os.Stat(b)
	if err != nil {
		// The output file need not exist yet; absence means it cannot alias.
		return false
	}
	return os.SameFile(aInfo, bInfo)
}

type progressReader struct {
	src         io.Reader
	dst         io.Writer
	every, next int64
	total       int64
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	r.total += int64(n)
	if r.total >= r.next {
		fmt.Fprintf(r.dst, "goredact: bytes_read=%d\n", r.total)
		for r.next <= r.total {
			r.next += r.every
		}
	}
	return n, err
}

func writeStats(name string, stats goredact.Stats, stderr io.Writer) error {
	if name == "" {
		return nil
	}
	dst := stderr
	var f *os.File
	if name != "-" {
		var err error
		f, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("goredact: cannot open statistics output: %w", err)
		}
		defer f.Close()
		dst = f
	}
	if err := json.NewEncoder(dst).Encode(stats); err != nil {
		return errors.New("goredact: cannot write statistics")
	}
	return nil
}

func safeScanError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.New("goredact: scan canceled")
	}
	var readErr *goredact.ReadError
	if errors.As(err, &readErr) {
		return errors.New("goredact: input read failed")
	}
	var writeErr *goredact.WriteError
	if errors.As(err, &writeErr) {
		return errors.New("goredact: output write failed")
	}
	return errors.New("goredact: scan failed")
}
