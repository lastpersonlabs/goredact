# Large-corpus benchmarks

`tools/benchreport` is the reproducible performance suite for the streaming
engine. It generates bytes as they are read, so no large fixture is checked in
or retained in memory. The generator seed (`0x4752440000000001`) and exact
corpus size are included in every JSON report.

## Matrix

The default run covers 100 MiB, 500 MiB, and 1 GiB inputs across:

- `quiet`: realistic log records without detector triggers;
- `keyword-dense`: operational keywords and many rejected trigger-like values;
- `adversarial`: high candidate pressure and near-miss validator inputs;
- `confirmed-secret`: deterministic syntactically valid tokens (test values,
  never credentials);
- fast, balanced, and deep profiles; and
- raw and newline record-aware output.

Each profile/scenario also has a `match` phase which runs only the trigger
automaton. `validate+redact` runs the complete streaming engine. Keeping these
rows separate makes validator cost visible instead of attributing it to string
matching.

Run the complete matrix (it processes tens of GiB in total):

```sh
make bench-large ARGS='-output benchmark-linux-amd64.json'
```

For iteration, select a subset:

```sh
go run ./tools/benchreport -sizes 100MiB \
  -scenarios adversarial,confirmed-secret -profiles balanced \
  -modes raw,record-aware -output smoke.json
```

The report records wall and process CPU time, throughput, allocation bytes and
count, process peak RSS, matcher/validator candidates, confirmed redactions and
bytes, and output/input compression ratio. Peak RSS is the process high-water
mark, so rows later in a single run may inherit an earlier maximum.

## Regression detection

`make bench-ci` runs a 16 MiB stress subset with deliberately conservative
absolute throughput and allocation budgets. CI uploads its JSON result. This
catches gross regressions without making shared-runner timing noise block
normal changes.

For controlled runners, compare against a report from the same OS,
architecture, Go version, CPU model, and power configuration:

```sh
go run ./tools/benchreport -sizes 100MiB -profiles balanced \
  -baseline baseline.json -max-regression .15 -output candidate.json
```

The command fails if any matching row loses more than the allowed throughput.
Reports from a different OS/architecture are rejected rather than compared.

## v0.1.0 release smoke result

On 2026-08-14, the v0.1.0 release candidate processed the reproducible 100 MiB
quiet corpus in balanced/raw `validate+redact` mode at **723.38 MiB/s** wall
throughput on a 24-vCPU linux/amd64 host running Go 1.26.6. The scanning path
uses one goroutine, so this row measures one-core throughput. The matcher-only
row measured 689.41 MiB/s. The full row allocated 265,720 bytes in 8
allocations and the process high-water RSS was 29,179,904 bytes. This exceeds
the 250 MiB/s/core target for the representative quiet-agent-log case. Results
are host specific; use the full dedicated-host matrix below for cross-release
claims.

## One-core comparison with Gitleaks

On 2026-08-14, GoRedact at commit `eb51eeddffbf` and Gitleaks 8.30.1-1 scanned
the same deterministic 512 MiB `quiet` corpus. One warm-up was followed by
three measured runs. Both processes were pinned to CPU 0 with `taskset`, and
`GOMAXPROCS=1` prevented either Go runtime from using another core. The input
was one file on tmpfs so that each tool had one process invocation and storage
latency did not dominate the measurement.

| Tool | Median wall time | Throughput | Median peak RSS |
| --- | ---: | ---: | ---: |
| GoRedact, balanced profile | 0.73 s | 701.37 MiB/s | 6,944 KiB |
| Gitleaks, default rules | 71.24 s | 7.19 MiB/s | 56,048 KiB |

GoRedact was **97.6x faster** on this workload. Its measured wall times were
0.73, 0.73, and 0.74 seconds; Gitleaks measured 70.89, 71.24, and 75.68
seconds. GoRedact streamed its redacted output to `/dev/null`. Gitleaks scanned
the containing directory with Git history, archive extraction, and decoding
disabled and wrote a redacted JSON report. Neither tool reported a secret.

The host was an AMD Ryzen 9 9900X (12 physical cores, 24 logical CPUs, up to
5,662 MHz, 64 MiB L3) with 64,912,039,936 bytes of RAM. It ran Arch Linux,
kernel 7.1.8-arch1-3, on x86-64 with Go 1.26.6-X:nodwarf5. The corpus SHA-256
was `e71ea70986c32622aa5640effa32f60709c890e6c600f53a479a0bae54e39755`.

This is a throughput comparison, not a detection-accuracy comparison. The
tools have different rules and behavior, and there is no standard public
secret-scanner performance corpus. The quiet corpus represents ordinary log
text without detector triggers and is useful for measuring baseline scanning
cost, but it does not establish relative recall or precision.

Reproduce the run on Linux with zsh and util-linux `taskset`:

```sh
go build -o /tmp/goredact ./cmd/goredact
go run ./tools/corpusfiles -output /tmp/goredact-corpus -scenario quiet \
  -files 1 -file-size 536870912
RUNS=3 zsh ./scripts/benchmark-gitleaks.zsh \
  /tmp/goredact-corpus/corpus-000.log /tmp/goredact "$(command -v gitleaks)"
```

## One-core comparison with Betterleaks

On 2026-08-14, GoRedact at commit `d71e6383eca4` and
[Betterleaks](https://github.com/betterleaks/betterleaks) v1.7.4 — the
successor scanner to Gitleaks from the same authors — scanned the same
deterministic 512 MiB `quiet` corpus under the same protocol as the Gitleaks
comparison above, on the same host: one warm-up followed by three measured
runs, both processes pinned to CPU 0 with `taskset`, `GOMAXPROCS=1`, and one
input file on tmpfs.

| Tool | Median wall time | Throughput | Median peak RSS |
| --- | ---: | ---: | ---: |
| GoRedact, balanced profile | 0.73 s | 701.37 MiB/s | 7,304 KiB |
| Betterleaks, default rules | 4.52 s | 113.27 MiB/s | 41,528 KiB |

GoRedact was **6.2x faster** on this workload. Its measured wall times were
0.73, 0.73, and 0.74 seconds; Betterleaks measured 4.52, 4.52, and 4.51
seconds, a large improvement over Gitleaks on the identical corpus. GoRedact
streamed its redacted output to `/dev/null`. Betterleaks scanned the
containing directory with archive extraction and decoding disabled and wrote a
redacted JSON report. Neither tool reported a secret. As with the Gitleaks
comparison, this measures baseline scanning throughput, not relative recall or
precision.

Reproduce the run on Linux with zsh and util-linux `taskset`:

```sh
go build -o /tmp/goredact ./cmd/goredact
go run ./tools/corpusfiles -output /tmp/goredact-corpus -scenario quiet \
  -files 1 -file-size 536870912
RUNS=3 zsh ./scripts/benchmark-betterleaks.zsh \
  /tmp/goredact-corpus/corpus-000.log /tmp/goredact "$(command -v betterleaks)"
```

## Local Codex and Claude session comparison

On 2026-08-14, a local supporting benchmark scanned every JSONL session under
`~/.codex/sessions` and `~/.claude/projects`. The private corpus contained 976
files and 658,454,891 bytes (627.95 MiB): 626 Codex files and 350 Claude files.
Caches, plugins, databases, generated images, file history, and other
non-session state were excluded. The session contents and reports were not
retained.

The same temporary copy of the corpus was scanned by the current GoRedact
working tree with the balanced profile, Betterleaks 1.7.4, and Gitleaks
8.30.1-1. Each process was pinned to logical CPU 0 with `taskset -c 0`, and
`GOMAXPROCS=1` limited the Go scheduler to one OS thread. All three used their
directory-scanning mode. Git history, archive extraction, and recursive
decoding were disabled; Betterleaks network validation was left disabled.
Reports used JSON with matched secrets fully redacted. GoRedact wrote its
report to `/dev/null`; the other scanners wrote temporary redacted reports,
which were deleted with the corpus after the run. Standard output and scanner
logs were suppressed so session contents and findings were not printed.

One warm-up preceded three measured GoRedact and Betterleaks runs. Gitleaks
did not complete a clean measured pass within three minutes and was stopped,
so its row is a conservative bound rather than a median:

| Tool | Measured wall times | Median wall time | Throughput | Median peak RSS | Relative wall time |
| --- | ---: | ---: | ---: | ---: | ---: |
| GoRedact, balanced profile | 0.99, 0.98, 0.99 s | **0.99 s** | **634.29 MiB/s** | 12,580 KiB | 1x |
| Betterleaks 1.7.4, default rules | 27.61, 26.51, 27.47 s | **27.47 s** | **22.86 MiB/s** | 181,852 KiB | **27.8x slower** |
| Gitleaks 8.30.1-1, default rules | >180 s, stopped | >180 s | <3.49 MiB/s | not recorded | **>181x slower** |

The corresponding user CPU times were 0.93, 0.92, and 0.93 seconds for
GoRedact and 13.56, 13.02, and 13.48 seconds for Betterleaks. By median user
CPU time, GoRedact was **14.5x faster** (675.22 versus 46.58 MiB/s). GoRedact
reported 1,845 findings, but only the count was observed; this benchmark did
not compare finding counts because the scanners have different rules and
semantics.

The commands had the following shape, with a fresh report path for each
measured run:

```sh
mkdir -p /tmp/session-corpus
find ~/.codex/sessions ~/.claude/projects -type f -name '*.jsonl' \
  -exec cp --parents -t /tmp/session-corpus {} +

taskset -c 0 env GOMAXPROCS=1 /tmp/goredact dir \
  -profile balanced -report-format json -report-path /dev/null -exit-code 0 \
  /tmp/session-corpus

taskset -c 0 env GOMAXPROCS=1 betterleaks dir /tmp/session-corpus \
  --max-decode-depth 0 --max-archive-depth 0 --redact=100 \
  --no-banner --no-color --log-level error --report-format json \
  --report-path /tmp/betterleaks-report.json --exit-code 0

taskset -c 0 env GOMAXPROCS=1 gitleaks detect --no-git \
  --source /tmp/session-corpus --max-decode-depth 0 --max-archive-depth 0 \
  --redact=100 --no-banner --no-color --log-level error \
  --report-format json --report-path /tmp/gitleaks-report.json --exit-code 0
```

This local run was performed on the AMD Ryzen 9 9900X host described above,
but inside a sandbox that appeared to throttle sustained CPU use: Betterleaks'
median wall time was about twice its user CPU time, while GoRedact's short run
could use the available burst capacity. Wall time describes the observed local
experience, but the wall-time ratios should not be treated as dedicated-host
release claims. The CPU-time ratio is less sensitive to that quota. The corpus
is also private and candidate-heavy, so its exact result cannot be reproduced
elsewhere; the procedure can be repeated on another session collection.

As in the synthetic comparisons, these figures measure throughput, not recall
or precision. Different finding counts must not be interpreted as an accuracy
ranking without a labeled ground-truth corpus.

## Producing release reports

Run the full matrix independently on dedicated `linux/amd64` and `linux/arm64`
hosts. Do not emulate arm64 for headline numbers. Record the CPU model and
count, RAM, OS and kernel, Go version, commit, CPU governor or host class, and
the median of the measured runs beside each JSON artifact.

Use at least three runs after one warm-up. Summarise median throughput per
scenario/profile/phase, maximum allocation ratio and RSS, candidate density,
redaction density, and record-aware overhead. Retain raw reports so later
releases can use `-baseline` on equivalent hardware.
