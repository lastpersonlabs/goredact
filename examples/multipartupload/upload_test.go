package multipartupload

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/lastpersonlabs/goredact"
)

type fakeClient struct {
	data                   bytes.Buffer
	begin, complete, abort int
	failPart, failComplete bool
	partSizes              []int64
}

func (c *fakeClient) Begin(context.Context) (Upload, error) {
	c.begin++
	return "upload", nil
}
func (c *fakeClient) UploadPart(_ context.Context, _ Upload, n int, body io.Reader, size int64) (Part, error) {
	if c.failPart {
		return nil, errors.New("remote failure")
	}
	got, err := io.Copy(&c.data, body)
	if err != nil || got != size {
		return nil, errors.New("body failure")
	}
	c.partSizes = append(c.partSizes, size)
	return n, nil
}
func (c *fakeClient) Complete(context.Context, Upload, []Part) error {
	c.complete++
	if c.failComplete {
		return errors.New("remote failure")
	}
	return nil
}
func (c *fakeClient) Abort(context.Context, Upload) error { c.abort++; return nil }

func TestRedactCompressUploadCompletesBoundedParts(t *testing.T) {
	engine, err := goredact.New(goredact.Config{Profile: goredact.ProfileFast})
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Repeat("prefix AWS_ACCESS_KEY_ID=AKIAUJZDEGXDNCF32EPF suffix\n", 200)
	client := new(fakeClient)
	var progress []Progress
	stats, err := RedactCompressUpload(context.Background(), client, engine, strings.NewReader(input), Options{
		PartSize: 257,
		Progress: func(p Progress) { progress = append(progress, p) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Findings != 200 || client.complete != 1 || client.abort != 0 {
		t.Fatalf("stats/completion = %+v, complete=%d abort=%d", stats, client.complete, client.abort)
	}
	for _, size := range client.partSizes {
		if size > 257 {
			t.Fatalf("part exceeded bound: %d", size)
		}
	}
	if len(progress) == 0 || progress[len(progress)-1].BytesRead != int64(len(input)) {
		t.Fatalf("progress = %+v", progress)
	}
	decoder, err := zstd.NewReader(bytes.NewReader(client.data.Bytes()), zstd.WithDecoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(decoder)
	decoder.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(decoded, []byte("AKIAUJZDEGXDNCF32EPF")) || !bytes.Contains(decoded, []byte("[REDACTED]")) {
		t.Fatal("uploaded object did not contain only redacted content")
	}
}

func TestRedactCompressUploadAbortsEveryFailure(t *testing.T) {
	tests := []struct {
		name   string
		client *fakeClient
		src    io.Reader
		cancel bool
	}{
		{name: "upload", client: &fakeClient{failPart: true}, src: strings.NewReader("data")},
		{name: "complete", client: &fakeClient{failComplete: true}, src: strings.NewReader("data")},
		{name: "scan", client: new(fakeClient), src: io.MultiReader(strings.NewReader("data"), errorReader{})},
		{name: "canceled", client: new(fakeClient), src: strings.NewReader("data"), cancel: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := goredact.New(goredact.Config{})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if tt.cancel {
				cancel()
			} else {
				defer cancel()
			}
			_, err = RedactCompressUpload(ctx, tt.client, engine, tt.src, Options{PartSize: 4})
			if err == nil {
				t.Fatal("expected failure")
			}
			if tt.client.complete > 0 && tt.name != "complete" {
				t.Fatal("partial object completed")
			}
			if tt.client.abort != 1 {
				t.Fatalf("abort calls = %d", tt.client.abort)
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("source failure") }
