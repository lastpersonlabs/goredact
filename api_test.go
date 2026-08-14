package goredact_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lastpersonlabs/goredact"
)

func TestModuleRootAPI(t *testing.T) {
	engine, err := goredact.New(goredact.Config{
		CustomRules: []goredact.CustomRule{{
			ID:         "test-token",
			Triggers:   []string{"secret"},
			Confidence: goredact.ConfidenceHigh,
			Validate: func(_ []byte, start, end int) (int, int, bool) {
				return start, end, true
			},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var output strings.Builder
	stats, err := engine.Redact(context.Background(), &output, strings.NewReader("a secret value"))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if got, want := output.String(), "a [REDACTED] value"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if stats.Findings != 1 {
		t.Fatalf("Findings = %d, want 1", stats.Findings)
	}

	if _, err := goredact.New(goredact.Config{Profile: goredact.Profile(99)}); !errors.Is(err, goredact.ErrInvalidConfig) {
		t.Fatalf("invalid profile error = %v, want ErrInvalidConfig", err)
	}
	if len(goredact.BuiltinRules()) == 0 {
		t.Fatal("BuiltinRules returned no rules")
	}
}
