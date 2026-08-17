package rules

import (
	"math"
	"strings"
	"testing"
)

// deepOnlyRuleID and fastRuleID are real built-in rule IDs used to pin
// EnableRules' interaction with Profile: generic-secret-assignment only
// activates at ProfileDeep, github-pat activates at every profile.
const (
	deepOnlyRuleID = "generic-secret-assignment"
	fastRuleID     = "github-pat"
)

func TestBuildEnableRulesOverridesProfileGate(t *testing.T) {
	set, err := Build(BuildOptions{Profile: ProfileBalanced, EnableRules: []string{deepOnlyRuleID}})
	if err != nil {
		t.Fatalf("Build() error = %v, want a rule set activating the deep-only rule", err)
	}
	ids := set.SortedIDs()
	if len(ids) != 1 || ids[0] != deepOnlyRuleID {
		t.Fatalf("SortedIDs() = %v, want only %q", ids, deepOnlyRuleID)
	}
}

func TestBuildEnableRulesMixedGatedAndUngated(t *testing.T) {
	set, err := Build(BuildOptions{Profile: ProfileFast, EnableRules: []string{deepOnlyRuleID, fastRuleID}})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	ids := set.SortedIDs()
	if len(ids) != 2 || ids[0] != deepOnlyRuleID || ids[1] != fastRuleID {
		t.Fatalf("SortedIDs() = %v, want [%q %q]", ids, deepOnlyRuleID, fastRuleID)
	}
}

func TestBuildEnableRulesUnknownIDRejected(t *testing.T) {
	_, err := Build(BuildOptions{Profile: ProfileBalanced, EnableRules: []string{"not-a-real-rule"}})
	if err == nil || !strings.Contains(err.Error(), "unknown rule ID") {
		t.Fatalf("Build() error = %v, want an unknown-rule-ID error", err)
	}
}

func TestBuildEmptyActiveSetRejected(t *testing.T) {
	_, err := Build(BuildOptions{Profile: ProfileBalanced, EnableRules: []string{deepOnlyRuleID}, DisableRules: []string{deepOnlyRuleID}})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("Build() error = %v, want an empty-rule-set error", err)
	}
}

func TestBuildWithoutEnableRulesAppliesProfileGate(t *testing.T) {
	set, err := Build(BuildOptions{Profile: ProfileBalanced})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range set.SortedIDs() {
		if id == deepOnlyRuleID {
			t.Fatalf("deep-only rule %q active at ProfileBalanced without EnableRules", deepOnlyRuleID)
		}
	}
}

// validCustomRule returns a shape-valid custom rule whose window is set by
// the mutator, for window-bounds tests.
func validCustomRule() Rule {
	return Rule{
		ID:         "c-test",
		Triggers:   []Trigger{{Literal: "TRIG"}, {Literal: "T"}},
		Validate:   func([]byte, int, int) (int, int, bool) { return 0, 0, false },
		Confidence: ConfidenceMedium,
		Custom:     true,
	}
}

// TestValidateRuleRejectsOverflowingWindows is the ENG-194 regression: a
// MaxInt lookahead/lookbehind used to wrap the window sum in Build to a
// tiny value, pass validation, and later panic the engine's slice
// indexing. Every case below must be rejected by validateRule with an
// error, not silently accepted.
func TestValidateRuleRejectsOverflowingWindows(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Rule)
	}{
		{"MaxLookahead = MaxInt", func(r *Rule) { r.MaxLookahead = math.MaxInt }},
		{"MaxLookbehind = MaxInt", func(r *Rule) { r.MaxLookbehind = math.MaxInt }},
		{"both bounds = MaxInt", func(r *Rule) { r.MaxLookbehind = math.MaxInt; r.MaxLookahead = math.MaxInt }},
		{"lookahead over limit", func(r *Rule) { r.MaxLookahead = maxValidationWindow }},
		{"lookbehind over limit", func(r *Rule) { r.MaxLookbehind = maxValidationWindow }},
		{"total window over limit", func(r *Rule) { r.MaxLookbehind = maxValidationWindow / 2; r.MaxLookahead = maxValidationWindow/2 + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validCustomRule()
			tc.mut(&r)
			if err := validateRule(r); err == nil {
				t.Fatalf("validateRule() = nil, want window-bounds error for %s", tc.name)
			}
		})
	}
}

// TestValidateRuleAcceptsBoundaryWindow pins the limit's edge: a window of
// exactly maxValidationWindow bytes (longest trigger "TRIG" is 4) is valid,
// one byte over is not.
func TestValidateRuleAcceptsBoundaryWindow(t *testing.T) {
	r := validCustomRule()
	r.MaxLookbehind = maxValidationWindow / 2
	r.MaxLookahead = maxValidationWindow - maxValidationWindow/2 - 4
	if err := validateRule(r); err != nil {
		t.Fatalf("validateRule() error = %v, want acceptance at the window limit", err)
	}
	r.MaxLookahead++
	if err := validateRule(r); err == nil {
		t.Fatal("validateRule() = nil for a window one byte over the limit")
	}
}

// TestBuildRejectsOverflowingWindows confirms the rejection surfaces from
// Build (and therefore goredact.New), before any engine slice indexing.
func TestBuildRejectsOverflowingWindows(t *testing.T) {
	cases := []struct {
		name       string
		lookbehind int
		lookahead  int
	}{
		{"MaxLookahead = MaxInt", 0, math.MaxInt},
		{"MaxLookbehind = MaxInt", math.MaxInt, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validCustomRule()
			r.MaxLookbehind = tc.lookbehind
			r.MaxLookahead = tc.lookahead
			if _, err := Build(BuildOptions{Profile: ProfileBalanced, CustomRules: []Rule{r}}); err == nil {
				t.Fatal("Build() = nil, want window-bounds error for overflowing custom rule")
			}
		})
	}
}

// TestBuildBoundaryWindowMaxWindow proves the maxWindow sum in Build does
// not wrap: a rule whose window equals maxValidationWindow yields exactly
// that MaxWindow, not a wrapped tiny value.
func TestBuildBoundaryWindowMaxWindow(t *testing.T) {
	r := validCustomRule()
	r.MaxLookbehind = maxValidationWindow / 2
	r.MaxLookahead = maxValidationWindow - maxValidationWindow/2 - 4
	set, err := Build(BuildOptions{Profile: ProfileBalanced, CustomRules: []Rule{r}})
	if err != nil {
		t.Fatalf("Build() error = %v, want acceptance at the window limit", err)
	}
	if got := set.MaxWindow(); got != maxValidationWindow {
		t.Fatalf("MaxWindow() = %d, want %d (window sum must not wrap)", got, maxValidationWindow)
	}
}
