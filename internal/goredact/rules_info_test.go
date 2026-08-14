package goredact

import (
	"sort"
	"strings"
	"testing"
)

// idSet builds a set of rule IDs from a []RuleInfo, for subset checks.
func idSet(rs []RuleInfo) map[string]bool {
	m := make(map[string]bool, len(rs))
	for _, r := range rs {
		m[r.ID] = true
	}
	return m
}

func isSortedByID(rs []RuleInfo) bool {
	return sort.SliceIsSorted(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
}

// TestBuiltinRules checks BuiltinRules reports every built-in regardless of
// profile, sorted by ID, and consistent with the compiled deep profile
// (which by construction includes every built-in).
func TestBuiltinRules(t *testing.T) {
	builtins := BuiltinRules()
	if len(builtins) == 0 {
		t.Fatal("BuiltinRules() returned no rules")
	}
	if !isSortedByID(builtins) {
		t.Error("BuiltinRules() is not sorted by ID")
	}
	for _, r := range builtins {
		if r.Custom {
			t.Errorf("builtin rule %q reported Custom = true", r.ID)
		}
	}

	deep := mustEngine(t, Config{Profile: ProfileDeep})
	deepIDs := idSet(deep.ActiveRules())
	if len(deepIDs) != len(builtins) {
		t.Fatalf("ProfileDeep has %d active rules, want %d (all builtins)", len(deepIDs), len(builtins))
	}
	for _, r := range builtins {
		if !deepIDs[r.ID] {
			t.Errorf("builtin %q missing from ProfileDeep", r.ID)
		}
	}
}

// TestActiveRulesProfileNesting checks fast ⊆ balanced ⊆ deep, that the
// nesting is strict where expected (balanced adds rules over fast) and
// non-strict where documented (deep == balanced in v0.1, since no built-in
// rule is deep-only), and that ActiveRules is sorted and copies (no
// internal state leaked).
func TestActiveRulesProfileNesting(t *testing.T) {
	fast := mustEngine(t, Config{Profile: ProfileFast}).ActiveRules()
	balanced := mustEngine(t, Config{Profile: ProfileBalanced}).ActiveRules()
	deep := mustEngine(t, Config{Profile: ProfileDeep}).ActiveRules()

	for _, rs := range [][]RuleInfo{fast, balanced, deep} {
		if !isSortedByID(rs) {
			t.Error("ActiveRules() is not sorted by ID")
		}
	}

	fastIDs, balancedIDs, deepIDs := idSet(fast), idSet(balanced), idSet(deep)

	for id := range fastIDs {
		if !balancedIDs[id] {
			t.Errorf("fast rule %q missing from balanced", id)
		}
	}
	for id := range balancedIDs {
		if !deepIDs[id] {
			t.Errorf("balanced rule %q missing from deep", id)
		}
	}
	if len(fast) >= len(balanced) {
		t.Errorf("balanced (%d) should add rules over fast (%d)", len(balanced), len(fast))
	}
	// v0.1: no built-in rule is deep-only, so deep == balanced exactly.
	if len(deep) != len(balanced) {
		t.Errorf("deep (%d) should equal balanced (%d) in v0.1 (no deep-only rules yet)", len(deep), len(balanced))
	}

	// Mutating the returned slice must not affect the Engine.
	e := mustEngine(t, Config{Profile: ProfileFast})
	rs := e.ActiveRules()
	if len(rs) == 0 {
		t.Fatal("expected at least one active rule")
	}
	rs[0].ID = "tampered"
	rs2 := e.ActiveRules()
	if rs2[0].ID == "tampered" {
		t.Fatal("ActiveRules() leaked internal state: mutation observed across calls")
	}
}

// TestActiveRulesReflectsEnableDisable checks EnableRules/DisableRules are
// reflected in ActiveRules.
func TestActiveRulesReflectsEnableDisable(t *testing.T) {
	e := mustEngine(t, Config{
		Profile:      ProfileBalanced,
		DisableRules: []string{"aws-access-key-id"},
	})
	ids := idSet(e.ActiveRules())
	if ids["aws-access-key-id"] {
		t.Error("aws-access-key-id should be disabled")
	}

	e2 := mustEngine(t, Config{
		Profile:     ProfileBalanced,
		EnableRules: []string{"github-pat", "aws-access-key-id"},
	})
	rs2 := e2.ActiveRules()
	if len(rs2) != 2 {
		t.Fatalf("ActiveRules() = %d rules, want exactly the 2 enabled", len(rs2))
	}
	ids2 := idSet(rs2)
	if !ids2["github-pat"] || !ids2["aws-access-key-id"] {
		t.Errorf("ActiveRules() = %v, want github-pat and aws-access-key-id", ids2)
	}
}

// TestActiveRulesIncludesCustom checks a custom rule appears in
// ActiveRules with Custom == true, alongside the compiled ID/Confidence.
func TestActiveRulesIncludesCustom(t *testing.T) {
	e := mustEngine(t, Config{CustomRules: []CustomRule{{
		ID:         "internal-widget-token",
		Triggers:   []string{"WIDGET-"},
		Confidence: ConfidenceHigh,
		Validate: func(w []byte, ts, te int) (int, int, bool) {
			return ts, te, true
		},
	}}})
	rs := e.ActiveRules()
	var found *RuleInfo
	for i := range rs {
		if rs[i].ID == "internal-widget-token" {
			found = &rs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("ActiveRules() = %v, missing custom rule", idSet(rs))
	}
	if !found.Custom {
		t.Error("custom rule reported Custom = false")
	}
	if found.Confidence != ConfidenceHigh {
		t.Errorf("custom rule Confidence = %v, want %v", found.Confidence, ConfidenceHigh)
	}
}

// TestDefaultConfigSafety asserts New(Config{}) is safe-by-default: it
// selects ProfileBalanced (not the zero-value-looking ProfileFast), it
// includes the high-value deterministic fast rules, and it excludes
// nothing about the fast tier that a fast-only caller would expect to be
// present in fast. It also checks ProfileFast explicitly excludes the
// balanced-only contextual/generic rules.
func TestDefaultConfigSafety(t *testing.T) {
	e := mustEngine(t, Config{})
	if e.cfg.Profile != ProfileBalanced {
		t.Fatalf("New(Config{}).cfg.Profile = %v, want ProfileBalanced", e.cfg.Profile)
	}

	active := idSet(e.ActiveRules())
	wantPresent := []string{
		"aws-access-key-id",
		"github-pat",
		"pem-private-key",
		"authorization-bearer",
		"url-credentials",
	}
	for _, id := range wantPresent {
		if !active[id] {
			t.Errorf("default Engine missing high-value fast rule %q", id)
		}
	}

	balanced := mustEngine(t, Config{Profile: ProfileBalanced}).ActiveRules()
	if len(e.ActiveRules()) != len(balanced) {
		t.Errorf("default Engine has %d active rules, want %d (matching explicit ProfileBalanced)", len(e.ActiveRules()), len(balanced))
	}

	fastIDs := idSet(mustEngine(t, Config{Profile: ProfileFast}).ActiveRules())
	wantAbsentFromFast := []string{
		"cookie-session-token",
		"generic-api-key-assignment",
		"generic-password-assignment",
		"generic-bearer-like-token-assignment",
		"twilio-api-key-sid",
		"notion-internal-token",
	}
	for _, id := range wantAbsentFromFast {
		if fastIDs[id] {
			t.Errorf("ProfileFast unexpectedly includes balanced-only rule %q", id)
		}
	}
}

// TestCustomRulesDoNotAlterBuiltinSet proves adding CustomRules to a
// Config does not change the compiled builtin rule set: an Engine's
// builtin RuleInfo set (Custom == false entries) must be identical whether
// or not CustomRules is set, and the custom rule itself must participate
// in redaction end to end.
func TestCustomRulesDoNotAlterBuiltinSet(t *testing.T) {
	plain := mustEngine(t, Config{Profile: ProfileBalanced})
	withCustom := mustEngine(t, Config{
		Profile: ProfileBalanced,
		CustomRules: []CustomRule{{
			ID:         "acme-internal-token",
			Triggers:   []string{"ACME-TOK-"},
			Confidence: ConfidenceHigh,
			Validate: func(w []byte, ts, te int) (int, int, bool) {
				end := te
				for end < len(w) && w[end] != ' ' && w[end] != '\n' {
					end++
				}
				return ts, end, true
			},
		}},
	})

	builtinsOf := func(e *Engine) []RuleInfo {
		var out []RuleInfo
		for _, r := range e.ActiveRules() {
			if !r.Custom {
				out = append(out, r)
			}
		}
		return out
	}

	got, want := builtinsOf(withCustom), builtinsOf(plain)
	if len(got) != len(want) {
		t.Fatalf("builtin rule count with CustomRules = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("builtin rule[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	// The custom rule participates in redaction end to end.
	in := "credential dump: token=ACME-TOK-abc123def456 (end)\n"
	out, stats := redactAll(t, withCustom, strings.NewReader(in))
	if strings.Contains(out, "ACME-TOK-abc123def456") {
		t.Errorf("custom rule secret leaked in output: %q", out)
	}
	if stats.ByRule["acme-internal-token"] == 0 {
		t.Errorf("stats.ByRule = %v, want a finding for acme-internal-token", stats.ByRule)
	}
}
