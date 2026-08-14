// Package multipartupload demonstrates a bounded-memory redact, Zstandard,
// and multipart-upload pipeline. Plaintext flows directly from src into the
// redactor; it is never written to an intermediate file.
package multipartupload

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/lastpersonlabs/goredact"
)

const (
	DefaultPartSize = 8 * 1024 * 1024
	// MaxParts matches the common S3 multipart limit and also bounds retained
	// part metadata independently of input size.
	MaxParts     = 10_000
	abortTimeout = 30 * time.Second
)

// Client is the storage-specific multipart adapter. Implementations should
// make UploadPart consume body before returning.
type Client interface {
	Begin(context.Context) (Upload, error)
	UploadPart(context.Context, Upload, int, io.Reader, int64) (Part, error)
	Complete(context.Context, Upload, []Part) error
	Abort(context.Context, Upload) error
}

// Upload and Part are opaque values owned by Client.
type Upload any
type Part any

// Progress contains counts only and is safe to log. It never contains input
// or matched bytes.
type Progress struct{ BytesRead int64 }

type Options struct {
	PartSize int
	Progress func(Progress)
}

// RedactCompressUpload streams src through engine and a Zstandard writer into
// multipart upload. At most PartSize plus the engine's fixed buffers are held
// in memory. Any scan, compression, upload, completion, or cancellation error
// causes Abort to be attempted with a fresh bounded context.
func RedactCompressUpload(ctx context.Context, client Client, engine *goredact.Engine, src io.Reader, opts Options) (goredact.Stats, error) {
	if client == nil || engine == nil || src == nil {
		return goredact.Stats{}, errors.New("multipartupload: nil dependency")
	}
	partSize := opts.PartSize
	if partSize == 0 {
		partSize = DefaultPartSize
	}
	if partSize < 1 {
		return goredact.Stats{}, errors.New("multipartupload: invalid part size")
	}

	upload, err := client.Begin(ctx)
	if err != nil {
		return goredact.Stats{}, errors.New("multipartupload: begin failed")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	type result struct {
		stats goredact.Stats
		err   error
	}
	resultCh := make(chan result, 1)
	go func() {
		reader := io.Reader(src)
		if opts.Progress != nil {
			reader = &countingReader{src: src, report: opts.Progress}
		}
		zw, zerr := zstd.NewWriter(pw, zstd.WithEncoderConcurrency(1))
		if zerr != nil {
			_ = pw.CloseWithError(zerr)
			resultCh <- result{err: zerr}
			return
		}
		stats, scanErr := engine.Redact(ctx, zw, reader)
		if scanErr == nil {
			scanErr = zw.Close()
		}
		_ = pw.CloseWithError(scanErr)
		resultCh <- result{stats: stats, err: scanErr}
	}()

	abort := func() {
		abortCtx, abortCancel := context.WithTimeout(context.WithoutCancel(ctx), abortTimeout)
		defer abortCancel()
		_ = client.Abort(abortCtx, upload)
	}
	fail := func(uploadErr error) (goredact.Stats, error) {
		cancel()
		_ = pr.CloseWithError(uploadErr)
		res := <-resultCh
		abort()
		if uploadErr != nil {
			return res.stats, uploadErr
		}
		return res.stats, res.err
	}

	buf := make([]byte, partSize)
	parts := make([]Part, 0, 8)
	for number := 1; ; number++ {
		if number > MaxParts {
			return fail(errors.New("multipartupload: part limit exceeded"))
		}
		n, readErr := io.ReadFull(pr, buf)
		if n > 0 {
			part, uploadErr := client.UploadPart(ctx, upload, number, bytes.NewReader(buf[:n]), int64(n))
			if uploadErr != nil {
				return fail(errors.New("multipartupload: part upload failed"))
			}
			parts = append(parts, part)
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fail(nil)
		}
	}
	res := <-resultCh
	if res.err != nil {
		abort()
		return res.stats, errors.New("multipartupload: scan or compression failed")
	}
	if err := client.Complete(ctx, upload, parts); err != nil {
		abort()
		return res.stats, errors.New("multipartupload: completion failed")
	}
	return res.stats, nil
}

type countingReader struct {
	src    io.Reader
	report func(Progress)
	total  int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	r.total += int64(n)
	if n > 0 {
		r.report(Progress{BytesRead: r.total})
	}
	return n, err
}
