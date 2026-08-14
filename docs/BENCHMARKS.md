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

## Producing release reports

Run the full matrix independently on dedicated `linux/amd64` and `linux/arm64`
hosts. Do not emulate arm64 for headline numbers. Record the CPU model and
count, RAM, OS and kernel, Go version, commit, CPU governor or host class, and
the median of the measured runs beside each JSON artifact.

Use at least three runs after one warm-up. Summarise median throughput per
scenario/profile/phase, maximum allocation ratio and RSS, candidate density,
redaction density, and record-aware overhead. Retain raw reports so later
releases can use `-baseline` on equivalent hardware.
