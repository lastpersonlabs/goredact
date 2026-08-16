package rules

import (
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
