# Reference CLI and upload pipeline

The reference command shows how a product CLI should connect input directly
to goredact and connect redacted output directly to its destination. It does
not create plaintext temporary files.

```sh
# stdin to stdout
go run ./cmd/goredact -profile balanced <session.jsonl >session.redacted.jsonl

# file to a streaming zstd frame, with count-only progress and JSON stats
go run ./cmd/goredact \
  -input session.jsonl \
  -output session.redacted.jsonl.zst \
  -profile deep -zstd \
  -progress-bytes $((64 * 1024 * 1024)) \
  -stats session.stats.json
```

`-input -` and `-output -` select standard input and output. `-stats -` writes
JSON statistics to standard error. Progress is also written to standard error
and contains only a cumulative byte count. Neither channel includes matched
content. Output files use mode `0600` and are removed if scanning or writing
fails. A stream sent to stdout may already have delivered a redacted prefix on
failure, so callers must not publish it as a completed object.

## Multipart uploads

[`examples/multipartupload`](../examples/multipartupload/upload.go) supplies a
storage-neutral integration. Implement its `Client` interface with the object
store's create, upload-part, complete, and abort operations, then call
`RedactCompressUpload`. For S3-compatible APIs, `Upload` normally carries the
upload ID and each `Part` carries its ETag.

The pipeline is:

```text
source -> goredact -> zstd encoder -> io.Pipe -> bounded part buffer -> object store
```

Only one part (8 MiB by default), the zstd encoder's fixed workspace, and the
redactor's fixed buffers are resident. Input size therefore does not determine
peak memory; a 500 MiB input follows the same path as a small input. Encoder
concurrency is fixed at one to keep its workspace bounded. Retained part
metadata is capped at 10,000 entries; exceeding the cap aborts the upload.

The object is completed only after the scanner and compressor finish
successfully. Read, scan, compression, part-upload, completion, and cancellation
failures cancel the producer and attempt `Abort` using a fresh 30-second
context. This is important because the original context is commonly already
canceled. Storage lifecycle rules should still expire abandoned multipart
uploads in case the process is killed or the abort request cannot reach the
service.

## Product integration rules

- Stream from the original source into `Engine.Redact`; never first copy it to
  a temporary file.
- Compress and encrypt only after redaction. Never use a plaintext spill file
  between stages.
- Treat count-only progress and `Stats` as the only safe diagnostics. Do not
  log source reads, matched windows, or errors from custom readers verbatim.
- Publish/rename a local result atomically only after a successful scan. For
  remote objects, complete the multipart upload only after producer success.
- On cancellation or failure, close the pipe and abort the multipart upload.
