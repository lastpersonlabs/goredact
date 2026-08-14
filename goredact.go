package goredact

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/lastpersonlabs/goredact/internal/rules"
)

// DefaultChunkSize is the input buffer size used when Config.ChunkSize is
// zero.
const DefaultChunkSize = 256 * 1024

// DefaultMarker is the replacement text used when Config.Marker is empty.
const DefaultMarker = "[REDACTED]"

// Config configures an Engine. The zero value is a valid configuration
// using ProfileBalanced, DefaultChunkSize, and DefaultMarker.
type Config struct {
	// Profile selects the detection profile. Defaults to ProfileBalanced.
	Profile Profile

	// ChunkSize is the size in bytes of the fixed input buffer. Values
	// below the minimum required by the compiled rule set are rejected by
	// New. Defaults to DefaultChunkSize.
	ChunkSize int

	// Marker is the fixed replacement text written in place of each
	// redacted span. Defaults to DefaultMarker.
	Marker string

	// EnableRules, when non-empty, restricts detection to the listed rule
	// IDs (an allowlist). Unknown IDs are rejected by New.
	EnableRules []string

	// DisableRules removes the listed rule IDs from the active set (a
	// denylist, applied after EnableRules). Unknown IDs are rejected by
	// New.
	DisableRules []string

	// CustomRules adds caller-defined rules to the active set. Custom rule
	// IDs must not collide with built-in rule IDs.
	CustomRules []CustomRule

	// OnFinding, when non-nil, is invoked synchronously for each confirmed
	// finding during Redact, in input order. The Finding never contains
	// matched input bytes. The callback must not retain references past
	// its return and must be fast; it runs on the scanning path.
	OnFinding func(Finding)
}

// CustomRule is a caller-supplied detection rule.
//
// A CustomRule is located by literal trigger strings. When a trigger is
// found, Validate is invoked with a bounded window of surrounding bytes and
// decides whether a secret is present and which bytes to redact.
type CustomRule struct {
	// ID is the stable rule identifier. Required, must be unique.
	ID string

	// Triggers are the literal byte strings that activate the rule.
	// Required, each must be non-empty.
	Triggers []string

	// CaseFold, when true, matches triggers with ASCII case folding.
	CaseFold bool

	// Confidence reported for findings confirmed by this rule.
	Confidence Confidence

	// MaxLookbehind and MaxLookahead bound the validation window in bytes
	// before the trigger start and after the trigger end.
	MaxLookbehind int
	MaxLookahead  int

	// Validate inspects window, in which the trigger occupies
	// window[trigStart:trigEnd], and reports the half-open byte range
	// [start, end) within window to redact. Implementations must not
	// retain window, log it, or include its contents in any output.
	Validate func(window []byte, trigStart, trigEnd int) (start, end int, ok bool)
}

// Engine detects and redacts secrets from byte streams.
//
// An Engine is immutable after construction and safe for concurrent use by
// multiple goroutines; each Redact call maintains independent scan state.
type Engine struct {
	cfg    Config
	rules  *rules.Set
	marker []byte
}

// New compiles the active rule set for the configuration and returns a
// reusable Engine.
func New(cfg Config) (*Engine, error) {
	if !cfg.Profile.valid() {
		return nil, fmt.Errorf("%w: unknown profile %d", ErrInvalidConfig, int(cfg.Profile))
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = DefaultChunkSize
	}
	if cfg.ChunkSize < 0 {
		return nil, fmt.Errorf("%w: negative chunk size", ErrInvalidConfig)
	}
	if cfg.Marker == "" {
		cfg.Marker = DefaultMarker
	}
	set, err := rules.Build(rules.BuildOptions{
		Profile:      rules.Profile(cfg.Profile),
		EnableRules:  cfg.EnableRules,
		DisableRules: cfg.DisableRules,
		CustomRules:  customToInternal(cfg.CustomRules),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if min := set.MinChunkSize(); cfg.ChunkSize < min {
		return nil, fmt.Errorf("%w: chunk size %d below minimum %d required by rule set", ErrInvalidConfig, cfg.ChunkSize, min)
	}
	return &Engine{cfg: cfg, rules: set, marker: []byte(cfg.Marker)}, nil
}

// Redact copies src to dst, replacing every confirmed secret with the
// configured marker, and returns statistics about the scan.
//
// Redact streams: it never buffers more than a bounded window of input and
// never writes unredacted data to temporary storage. It returns the first
// error encountered: ctx.Err() on cancellation, a *ReadError on source
// failure, or a *WriteError on destination failure. On error, output
// already written remains valid redacted output; no unredacted confirmed
// secret has been emitted.
func (e *Engine) Redact(ctx context.Context, dst io.Writer, src io.Reader) (Stats, error) {
	return e.redact(ctx, dst, src)
}

// RuleSetVersion reports the version identifier of the compiled built-in
// rule set, for inclusion in caller diagnostics.
func (e *Engine) RuleSetVersion() string {
	return rules.Version
}

func customToInternal(in []CustomRule) []rules.Rule {
	out := make([]rules.Rule, 0, len(in))
	for _, c := range in {
		r := rules.Rule{
			ID:            c.ID,
			Triggers:      make([]rules.Trigger, 0, len(c.Triggers)),
			Confidence:    rules.Confidence(c.Confidence),
			MaxLookbehind: c.MaxLookbehind,
			MaxLookahead:  c.MaxLookahead,
			Validate:      c.Validate,
			Custom:        true,
		}
		for _, t := range c.Triggers {
			r.Triggers = append(r.Triggers, rules.Trigger{Literal: t, CaseFold: c.CaseFold})
		}
		out = append(out, r)
	}
	return out
}

// errNotImplemented is returned until the streaming engine lands (ENG-96).
var errNotImplemented = errors.New("goredact: streaming engine not implemented yet")

// redact is implemented in engine.go once the streaming engine exists.
// Until then it fails without consuming input.
var redactImpl func(e *Engine, ctx context.Context, dst io.Writer, src io.Reader) (Stats, error)

func (e *Engine) redact(ctx context.Context, dst io.Writer, src io.Reader) (Stats, error) {
	if redactImpl == nil {
		return Stats{}, errNotImplemented
	}
	return redactImpl(e, ctx, dst, src)
}
