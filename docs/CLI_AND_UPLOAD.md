# Reference CLI and upload pipeline

The reference command shows how a product CLI should connect input directly
to goredact and connect redacted output directly to its destination. It does
not create plaintext temporary files.

```sh
# stdin to stdout
go run ./cmd/goredact stream -profile balanced \
  <session.jsonl >session.redacted.jsonl

# file to a streaming zstd frame, with count-only progress and JSON stats
go run ./cmd/goredact stream \
  -input session.jsonl \
  -output session.redacted.jsonl.zst \
  -profile deep -zstd \
  -progress-bytes $((64 * 1024 * 1024)) \
  -stats session.stats.json
```

`stream -input -` and `stream -output -` select standard input and output.
`stream -stats -` writes
JSON statistics to standard error. Progress is also written to standard error
and contains only a cumulative byte count. Neither channel includes matched
content. Output files use mode `0600` and are removed if scanning or writing
fails. A stream sent to stdout may already have delivered a redacted prefix on
failure, so callers must not publish it as a completed object.

## Directory scanning and reports

`dir` recursively scans regular files without following symbolic links. It
does not write redacted copies; findings are collected into a report suitable
for review or CI systems. Paths are relative to the scan root, byte offsets
refer to the original file, and matched secret values are never included.

```sh
# Human- and machine-readable JSON on stdout.
goredact dir -report-format json -exit-code 0 ./workspace

# CI reports. The default exit code is 1 when findings are present.
goredact dir -report-format sarif -report-path findings.sarif ./workspace
goredact dir -report-format junit -report-path findings.xml ./workspace
goredact dir -report-format csv -report-path findings.csv ./workspace
```

Supported report formats are `json`, `csv`, `junit`, and `sarif`. JSON reports
also contain the schema identifier, selected profile, file count, and total
bytes scanned. `-exit-code N` selects the finding exit code from 1 through 125;
`-exit-code 0` makes findings a successful result. Operational failures still
exit with status 1. If the report already exists inside the scan root, it is
excluded from the input set.

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
