// Package accuracy provides the synthetic, non-production credential corpus
// used for detector accuracy and differential tests.
package accuracy

//go:generate go run ../../tools/corpusgen

// Format describes the kind of text surrounding a corpus fixture.
type Format string

const (
	FormatAgentJSON    Format = "agent-session-json"
	FormatAgentJSONL   Format = "agent-session-jsonl"
	FormatShell        Format = "shell-output"
	FormatGitDiff      Format = "git-diff"
	FormatEnv          Format = "environment-dump"
	FormatHTTPRequest  Format = "http-request"
	FormatHTTPResponse Format = "http-response"
	FormatMinified     Format = "minified"
	FormatEscaped      Format = "escaped-content"
	FormatAdversarial  Format = "keyword-adversarial-log"
)

// Fixture is one positive or negative example. Value is deliberately kept
// opaque to test diagnostics: callers should identify fixtures using RuleID,
// Positive, Ordinal and Format, never by printing Value.
type Fixture struct {
	RuleID   string
	Positive bool
	Ordinal  int
	Format   Format
	Value    string
}

// All returns a fresh copy of the corpus.
func All() []Fixture {
	out := make([]Fixture, len(generatedCorpus))
	copy(out, generatedCorpus)
	return out
}
