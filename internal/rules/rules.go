// Package rules defines the internal rule model shared by the matcher,
// the streaming engine, and the generated built-in rule tables.
package rules

import (
	"fmt"
	"sort"
)

// Version identifies the built-in rule-set revision. It is defined in the
// generated zz_generated_rules.go (ENG-97): it is derived from the
// canonical serialization of the generated rule table, so it changes
// exactly when generated rules change.

// Profile is a bitmask of the profiles a rule belongs to.
type Profile uint8

// Numbering starts at 1, matching the public goredact.Profile (whose zero
// value is reserved to mean "unspecified" so New(Config{}) can default to
// ProfileBalanced): goredact.New passes Profile(cfg.Profile) straight
// through as this type, so the two enums must stay numerically aligned.
const (
	profileUnspecified Profile = iota
	ProfileFast
	ProfileBalanced
	ProfileDeep
)

// Confidence mirrors the public confidence levels.
type Confidence uint8

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

// ValidateFunc inspects window, in which the trigger occupies
// window[trigStart:trigEnd], and reports the half-open range [start, end)
// within window to redact. Implementations must be pure functions of the
// window: no I/O, no logging, no retention of the window slice.
type ValidateFunc func(window []byte, trigStart, trigEnd int) (start, end int, ok bool)

// Trigger is a literal byte string that activates a rule.
type Trigger struct {
	Literal  string
	CaseFold bool
}

// Rule is one detection rule: triggers locate candidates cheaply, Validate
// confirms them within a bounded window.
type Rule struct {
	// ID is the stable rule identifier, e.g. "aws-access-key-id".
	ID string

	// Name is the human-readable rule name.
	Name string

	// Triggers are the literals that activate this rule.
	Triggers []Trigger

	// Validate confirms candidates. Required.
	Validate ValidateFunc

	// MinProfile is the least detailed profile that includes this rule:
	// a rule with MinProfile == ProfileFast runs in every profile, one
	// with MinProfile == ProfileDeep runs only in the deep profile.
	MinProfile Profile

	// Confidence is reported for findings confirmed by this rule.
	Confidence Confidence

	// MaxLookbehind and MaxLookahead bound the validation window in bytes
	// before the trigger start and after the trigger end.
	MaxLookbehind int
	MaxLookahead  int

	// Custom marks caller-supplied rules.
	Custom bool
}

// Set is the compiled, immutable active rule set for one Engine.
type Set struct {
	// Rules is the active rules in deterministic order (built-ins in
	// generation order, then custom rules in caller order).
	Rules []Rule

	// maxWindow is the largest MaxLookbehind + trigger length +
	// MaxLookahead over all active rules.
	maxWindow int
}

// BuildOptions selects and extends the built-in rule set.
type BuildOptions struct {
	Profile      Profile
	EnableRules  []string
	DisableRules []string
	CustomRules  []Rule
}

// builtins is populated by the generated rule tables (ENG-97). Kept as a
// function variable so the generated file lives in this package without an
// import cycle.
var builtins []Rule

// RegisterBuiltins installs the generated built-in rule table. It is called
// from generated code's init and must not be called twice.
func RegisterBuiltins(rs []Rule) {
	if builtins != nil {
		panic("rules: builtins registered twice")
	}
	builtins = rs
}

// Builtins returns the registered built-in rules.
func Builtins() []Rule { return builtins }

// Build compiles the active rule set for the given options.
func Build(opts BuildOptions) (*Set, error) {
	var enable map[string]bool
	if len(opts.EnableRules) > 0 {
		enable = make(map[string]bool, len(opts.EnableRules))
		for _, id := range opts.EnableRules {
			enable[id] = true
		}
	}
	disable := make(map[string]bool, len(opts.DisableRules))
	for _, id := range opts.DisableRules {
		disable[id] = true
	}

	known := make(map[string]bool, len(builtins))
	var active []Rule
	for _, r := range builtins {
		known[r.ID] = true
		if r.MinProfile > opts.Profile {
			continue
		}
		if enable != nil && !enable[r.ID] {
			continue
		}
		if disable[r.ID] {
			continue
		}
		active = append(active, r)
	}
	for _, id := range opts.EnableRules {
		if !known[id] {
			return nil, fmt.Errorf("unknown rule ID in EnableRules: %q", id)
		}
	}
	for _, id := range opts.DisableRules {
		if !known[id] {
			return nil, fmt.Errorf("unknown rule ID in DisableRules: %q", id)
		}
	}

	seen := make(map[string]bool, len(active)+len(opts.CustomRules))
	for _, r := range active {
		seen[r.ID] = true
	}
	for _, r := range opts.CustomRules {
		if err := validateRule(r); err != nil {
			return nil, err
		}
		if known[r.ID] || seen[r.ID] {
			return nil, fmt.Errorf("custom rule ID collides with existing rule: %q", r.ID)
		}
		seen[r.ID] = true
		active = append(active, r)
	}

	s := &Set{Rules: active}
	for _, r := range s.Rules {
		for _, t := range r.Triggers {
			if w := r.MaxLookbehind + len(t.Literal) + r.MaxLookahead; w > s.maxWindow {
				s.maxWindow = w
			}
		}
	}
	return s, nil
}

func validateRule(r Rule) error {
	if r.ID == "" {
		return fmt.Errorf("rule with empty ID")
	}
	if len(r.Triggers) == 0 {
		return fmt.Errorf("rule %q has no triggers", r.ID)
	}
	for _, t := range r.Triggers {
		if t.Literal == "" {
			return fmt.Errorf("rule %q has an empty trigger", r.ID)
		}
	}
	if r.Validate == nil {
		return fmt.Errorf("rule %q has no validator", r.ID)
	}
	if r.MaxLookbehind < 0 || r.MaxLookahead < 0 {
		return fmt.Errorf("rule %q has negative window bounds", r.ID)
	}
	return nil
}

// MaxWindow returns the largest lookbehind + trigger + lookahead over all
// active rules, i.e. the overlap the streaming engine must retain across
// chunk boundaries.
func (s *Set) MaxWindow() int { return s.maxWindow }

// MinChunkSize returns the smallest chunk size the streaming engine can
// operate with for this rule set.
func (s *Set) MinChunkSize() int {
	const floor = 4096
	if w := 2 * s.maxWindow; w > floor {
		return w
	}
	return floor
}

// SortedIDs returns the active rule IDs sorted, for diagnostics and tests.
func (s *Set) SortedIDs() []string {
	ids := make([]string, len(s.Rules))
	for i, r := range s.Rules {
		ids[i] = r.ID
	}
	sort.Strings(ids)
	return ids
}
