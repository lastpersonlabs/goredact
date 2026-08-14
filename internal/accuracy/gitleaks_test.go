package accuracy_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lastpersonlabs/goredact/internal/accuracy"
)

// TestGitleaksDifferential is an offline oracle. CI opts into the intentionally
// overlapping subset with GOREDACT_GITLEAKS_RULES (comma-separated goredact
// rule IDs). It never downloads Gitleaks or prints fixture/report contents.
func TestGitleaksDifferential(t *testing.T) {
	bin := os.Getenv("GITLEAKS_BIN")
	if bin == "" {
		var err error
		bin, err = exec.LookPath("gitleaks")
		if err != nil {
			t.Skip("gitleaks binary not installed; offline differential skipped")
		}
	}
	supported := csvSet(os.Getenv("GOREDACT_GITLEAKS_RULES"))
	if len(supported) == 0 {
		t.Skip("set GOREDACT_GITLEAKS_RULES to the intentionally supported oracle subset")
	}

	dir := t.TempDir()
	fixtureDir := filepath.Join(dir, "corpus")
	if err := os.Mkdir(fixtureDir, 0o700); err != nil {
		t.Fatal("create sanitized corpus directory")
	}
	type identity struct {
		rule     string
		positive bool
		ordinal  int
	}
	identities := map[string]identity{}
	logical := map[string]*metric{}
	for _, fixture := range accuracy.All() {
		if !supported[fixture.RuleID] {
			continue
		}
		name := fmt.Sprintf("%s__%t__%d.txt", fixture.RuleID, fixture.Positive, fixture.Ordinal)
		if err := os.WriteFile(filepath.Join(fixtureDir, name), []byte(fixture.Value), 0o600); err != nil {
			t.Fatalf("write fixture rule=%s ordinal=%d", fixture.RuleID, fixture.Ordinal)
		}
		identities[name] = identity{fixture.RuleID, fixture.Positive, fixture.Ordinal}
		if logical[fixture.RuleID] == nil {
			logical[fixture.RuleID] = &metric{}
		}
		if fixture.Positive {
			logical[fixture.RuleID].positive++
		} else {
			logical[fixture.RuleID].negative++
		}
	}
	for rule := range supported {
		if logical[rule] == nil {
			t.Fatalf("oracle subset contains unknown rule=%s", rule)
		}
	}
	report := filepath.Join(dir, "report.json")
	cmd := exec.Command(bin, "detect", "--no-git", "--source", fixtureDir, "--report-format", "json", "--report-path", report, "--exit-code", "0")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	// Combined output is intentionally discarded: some Gitleaks versions
	// include matched secret material in verbose diagnostics.
	if err := cmd.Run(); err != nil {
		t.Fatalf("gitleaks oracle execution failed (output suppressed): %v", err)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal("gitleaks did not produce its JSON report")
	}
	var findings []struct {
		File string `json:"File"`
	}
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal("gitleaks report was not valid JSON")
	}
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[filepath.Base(finding.File)] = true
	}
	rules := make([]string, 0, len(logical))
	for rule := range logical {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	for _, rule := range rules {
		m := logical[rule]
		for name, id := range identities {
			if id.rule != rule || !seen[name] {
				continue
			}
			if id.positive {
				m.found++
			} else {
				m.falsePositive++
			}
		}
		t.Logf("gitleaks rule=%s recall=%d/%d false_positive=%d/%d", rule, m.found, m.positive, m.falsePositive, m.negative)
		if m.found != m.positive || m.falsePositive != 0 {
			t.Errorf("gitleaks differential mismatch rule=%s recall=%d/%d false_positive=%d/%d", rule, m.found, m.positive, m.falsePositive, m.negative)
		}
	}
}

func csvSet(value string) map[string]bool {
	out := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out[item] = true
		}
	}
	return out
}
