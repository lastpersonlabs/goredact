package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// profilesDocPath is docs/PROFILES.md relative to this package.
const profilesDocPath = "../../docs/PROFILES.md"

// TestProfilesDocMatchesBuiltins keeps docs/PROFILES.md from drifting away
// from the shipped rule table. The document is the human-facing rule
// inventory: readers use it to decide which profile to run and which rules
// a profile contains, so a stale row is a correctness problem, not a
// cosmetic one. Nothing regenerates the document, so this test is the gate.
//
// Only metadata is compared (IDs, names, profiles, confidences, trigger
// literals). No fixture, secret, or matched input is involved.
func TestProfilesDocMatchesBuiltins(t *testing.T) {
	doc := readProfilesDoc(t)

	t.Run("rule table", func(t *testing.T) {
		want := profilesDocRows()
		got := profilesDocTable(t, doc)

		if len(got) != len(want) {
			t.Errorf("docs/PROFILES.md lists %d rules, Builtins() has %d", len(got), len(want))
		}
		for i := 0; i < len(got) && i < len(want); i++ {
			if got[i] != want[i] {
				t.Errorf("docs/PROFILES.md table row %d is stale:\n  have: %s\n  want: %s", i+1, got[i], want[i])
			}
		}
		for i := len(want); i < len(got); i++ {
			t.Errorf("docs/PROFILES.md documents a rule that no longer exists:\n  have: %s", got[i])
		}
		for i := len(got); i < len(want); i++ {
			t.Errorf("docs/PROFILES.md is missing a rule:\n  want: %s", want[i])
		}
	})

	t.Run("total count", func(t *testing.T) {
		// "67 built-in rules as of this writing."
		m := regexp.MustCompile(`(?m)^(\d+) built-in rules as of this writing`).FindStringSubmatch(doc)
		if m == nil {
			t.Fatal("docs/PROFILES.md is missing the 'N built-in rules as of this writing' sentence")
		}
		if want := fmt.Sprint(len(Builtins())); m[1] != want {
			t.Errorf("docs/PROFILES.md claims %s built-in rules, Builtins() has %s", m[1], want)
		}
	})

	t.Run("per-profile counts", func(t *testing.T) {
		fast, balanced, deep := profileCounts()
		want := fmt.Sprintf(
			"Per-profile counts: `fast` = %d rules, `balanced` = %d rules (adds %d),\n`deep` = %d rules (adds %d, see above).",
			fast, balanced, balanced-fast, deep, deep-balanced,
		)
		if !strings.Contains(doc, want) {
			t.Errorf("docs/PROFILES.md per-profile counts are stale; expected to find:\n%s", want)
		}
	})
}

// profilesDocRows renders the Markdown table body the document must contain,
// in Builtins() order (ID-sorted, guarded by TestBuiltinsSortedAndNonEmpty).
func profilesDocRows() []string {
	rs := Builtins()
	rows := make([]string, 0, len(rs))
	for _, r := range rs {
		literals := make([]string, len(r.Triggers))
		for i, trigger := range r.Triggers {
			literals[i] = "`" + trigger.Literal + "`"
		}
		rows = append(rows, fmt.Sprintf(
			"| `%s` | %s | %s | %s | %s |",
			r.ID, r.Name, profileName(r.MinProfile), confidenceName(r.Confidence), strings.Join(literals, ", "),
		))
	}
	return rows
}

// profilesDocTable extracts the body rows of the document's rule table: the
// contiguous run of table lines following the header separator.
func profilesDocTable(t *testing.T, doc string) []string {
	t.Helper()

	const header = "| ID | Name | Min profile | Confidence | Triggers |"
	lines := strings.Split(doc, "\n")
	start := -1
	for i, line := range lines {
		if line == header {
			start = i + 2 // skip the header and its separator row
			break
		}
	}
	if start < 0 {
		t.Fatalf("docs/PROFILES.md is missing the rule table header %q", header)
	}
	if start > len(lines) || !strings.HasPrefix(lines[start-1], "| ---") {
		t.Fatal("docs/PROFILES.md rule table header is not followed by a separator row")
	}

	var rows []string
	for _, line := range lines[start:] {
		if !strings.HasPrefix(line, "|") {
			break
		}
		rows = append(rows, line)
	}
	return rows
}

// profileCounts reports how many built-in rules each profile activates. A
// rule runs in its MinProfile and in every more detailed profile.
func profileCounts() (fast, balanced, deep int) {
	for _, r := range Builtins() {
		switch r.MinProfile {
		case ProfileFast:
			fast++
		case ProfileBalanced:
			balanced++
		case ProfileDeep:
			deep++
		}
	}
	balanced += fast
	deep += balanced
	return fast, balanced, deep
}

func profileName(p Profile) string {
	switch p {
	case ProfileFast:
		return "fast"
	case ProfileBalanced:
		return "balanced"
	case ProfileDeep:
		return "deep"
	default:
		return fmt.Sprintf("Profile(%d)", uint8(p))
	}
}

func confidenceName(c Confidence) string {
	switch c {
	case ConfidenceLow:
		return "low"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	default:
		return fmt.Sprintf("Confidence(%d)", uint8(c))
	}
}

func readProfilesDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(profilesDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", profilesDocPath, err)
	}
	return string(data)
}
