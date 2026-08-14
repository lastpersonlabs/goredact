package accuracy_test

import "testing"

// TestBetterleaksDifferential is an offline oracle against Betterleaks, the
// successor scanner to Gitleaks. CI opts into the intentionally overlapping
// subset with GOREDACT_BETTERLEAKS_RULES (comma-separated goredact rule IDs).
// It never downloads Betterleaks or prints fixture/report contents.
func TestBetterleaksDifferential(t *testing.T) {
	runScannerDifferential(t, "betterleaks", "BETTERLEAKS_BIN", "GOREDACT_BETTERLEAKS_RULES", func(fixtureDir, reportPath string) []string {
		return []string{"dir", fixtureDir, "--report-format", "json", "--report-path", reportPath, "--exit-code", "0", "--no-banner", "--log-level", "error"}
	})
}
