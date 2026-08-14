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

## Release report scaffold

Run the full matrix independently on dedicated `linux/amd64` and `linux/arm64`
hosts. Do not emulate arm64 for headline numbers. Record the following beside
the two JSON artifacts:

| Field | linux/amd64 | linux/arm64 |
|---|---:|---:|
| CPU model / vCPU count | TODO | TODO |
| RAM | TODO | TODO |
| OS/kernel | TODO | TODO |
| Go version | TODO | TODO |
| Commit | TODO | TODO |
| Governor / host class | TODO | TODO |
| Median of runs | TODO | TODO |

Use at least three runs after one warm-up. Summarise median throughput per
scenario/profile/phase, maximum allocation ratio and RSS, candidate density,
redaction density, and record-aware overhead. Retain raw reports so later
releases can use `-baseline` on equivalent hardware.
