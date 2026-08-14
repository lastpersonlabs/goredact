package rules

import (
	"sort"
	"testing"
)

// TestBuiltinsSortedAndNonEmpty guards the ordering contract rulegen
// promises (ENG-97): built-in rules are registered in ID-sorted order, so
// adding an unrelated rule to the specs cannot reorder existing entries in
// Builtins() or in a compiled Set. This test exercises the real generated
// table (zz_generated_rules.go), produced by `go generate ./internal/rules`.
func TestBuiltinsSortedAndNonEmpty(t *testing.T) {
	rs := Builtins()
	if len(rs) == 0 {
		t.Fatal("Builtins() is empty; run `go generate ./internal/rules`")
	}

	ids := make([]string, len(rs))
	for i, r := range rs {
		ids[i] = r.ID
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("Builtins() not sorted by ID: %v", ids)
	}

	seen := make(map[string]bool, len(ids))
	for i, r := range rs {
		if r.ID == "" {
			t.Errorf("builtin rule at index %d has an empty ID", i)
		}
		if seen[r.ID] {
			t.Errorf("duplicate builtin rule ID: %q", r.ID)
		}
		seen[r.ID] = true
		if r.Validate == nil {
			t.Errorf("builtin rule %q has a nil Validate func", r.ID)
		}
		if len(r.Triggers) == 0 {
			t.Errorf("builtin rule %q has no triggers", r.ID)
		}
	}

	if Version == "" {
		t.Error("Version is empty")
	}
}
