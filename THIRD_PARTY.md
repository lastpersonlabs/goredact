# Third-party code provenance

This file is the provenance register for any vendored or adapted third-party
source code included in this repository.

## Current status

**No third-party code is vendored or adapted in this repository.** The core
library under the module root and `internal/` is original and stdlib-only.
The reference integrations use the pure-Go dependency recorded below.

The `licence-check` CI job (`.github/workflows/ci.yml`) enforces this by
scanning for copyright headers that do not attribute Last Person Labs and by
failing the build if this file is missing.

## Recording a new entry

If a future change vendors or adapts code from another project (for example,
a small algorithm lifted from a reference implementation, or a generated
table derived from a third-party corpus), add an entry below **before**
merging, and keep the copied code's licence header intact in the local file.
Each entry must record:

- **Source URL** — the exact upstream repository/file URL the code was taken
  from.
- **Commit** — the upstream commit hash (or release tag) the code was copied
  at, so provenance can be re-verified later.
- **Licence** — the upstream licence identifier (e.g. `MIT`, `Apache-2.0`,
  `BSD-3-Clause`) and confirmation that it is compatible with this project's
  MIT licence.
- **Local path** — where the adapted/vendored code lives in this repository.

### Entry template

```
### <short name of the vendored component>

- Source URL:
- Commit:
- Licence:
- Local path:
- Notes: (what was changed from upstream, if anything)
```

Entries are append-only; do not remove a historical entry even if the code is
later deleted, unless the entire file is being reset to reflect a clean
audit (note the reset in the PR description).

## External dependencies

### klauspost/compress

- Source URL: https://github.com/klauspost/compress
- Release: v1.18.0
- Licence file: https://github.com/klauspost/compress/blob/v1.18.0/LICENSE
- Licence: mixed by file. The module's primary terms are BSD-3-Clause;
  `gzhttp/*` is Apache-2.0; `s2/cmd/internal/readahead/*` and
  `s2/cmd/internal/filepathx/*` are MIT; and `snappy/*` plus
  `internal/snapref/*` carry BSD-3-Clause terms. This project directly imports
  `github.com/klauspost/compress/zstd`; its linked transitive packages from
  the module (`fse`, `huff0`, `internal/cpuinfo`, `internal/le`,
  `internal/snapref`, and `zstd/internal/xxhash`) are also covered by
  BSD-3-Clause terms. Those applicable terms are compatible with this
  project's MIT licence.
- Local use: `cmd/goredact` and `examples/multipartupload`
- Notes: pure-Go streaming Zstandard encoder; consumed as a Go module and not
  vendored or adapted. Binary redistributors must preserve the applicable
  copyright notice, conditions, and disclaimer as required by BSD-3-Clause.
