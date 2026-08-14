# Versioning and compatibility

goredact follows semantic versioning. Before v1.0, minor releases may add
detectors or API while patch releases are reserved for compatible fixes.

The exported Go API, profile names, rule IDs, finding metadata, and redaction
semantics are compatibility surfaces. Existing rule IDs are not repurposed.
New rules may increase redaction coverage in a profile; callers requiring a
frozen detector set should record `Engine.RuleSetVersion()` and use explicit
rule allowlists.

Generated reports record the Go version, platform, and rule-set version where
applicable. A release tag `vX.Y.Z` is immutable and triggers the repository's
release workflow after the full test gate passes.

The module supports the Go version declared in `go.mod`. The core library is
pure Go and stdlib-only. Optional command/example dependencies are outside the
core package's dependency path.
