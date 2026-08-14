package accuracy_test

import "testing"

// TestGitleaksDifferential is an offline oracle. CI opts into the intentionally
// overlapping subset with GOREDACT_GITLEAKS_RULES (comma-separated goredact
// rule IDs). It never downloads Gitleaks or prints fixture/report contents.
func TestGitleaksDifferential(t *testing.T) {
	runScannerDifferential(t, "gitleaks", "GITLEAKS_BIN", "GOREDACT_GITLEAKS_RULES", func(fixtureDir, reportPath string) []string {
		return []string{"detect", "--no-git", "--source", fixtureDir, "--report-format", "json", "--report-path", reportPath, "--exit-code", "0"}
	})
}
