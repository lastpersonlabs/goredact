package goredact

import (
	"errors"
	"strings"
	"testing"
)

func TestNewDefaults(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("New(Config{}) error: %v", err)
	}
	if e.cfg.ChunkSize != DefaultChunkSize {
		t.Errorf("ChunkSize = %d, want %d", e.cfg.ChunkSize, DefaultChunkSize)
	}
	if string(e.marker) != DefaultMarker {
		t.Errorf("marker = %q, want %q", e.marker, DefaultMarker)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"unknown profile", Config{Profile: Profile(99)}},
		{"negative chunk size", Config{ChunkSize: -1}},
		{"tiny chunk size", Config{ChunkSize: 1}},
		{"unknown enable rule", Config{EnableRules: []string{"no-such-rule"}}},
		{"unknown disable rule", Config{DisableRules: []string{"no-such-rule"}}},
		{"custom rule without ID", Config{CustomRules: []CustomRule{{
			Triggers: []string{"x"},
			Validate: func([]byte, int, int) (int, int, bool) { return 0, 0, false },
		}}}},
		{"custom rule without trigger", Config{CustomRules: []CustomRule{{
			ID:       "c1",
			Validate: func([]byte, int, int) (int, int, bool) { return 0, 0, false },
		}}}},
		{"custom rule without validator", Config{CustomRules: []CustomRule{{
			ID:       "c1",
			Triggers: []string{"x"},
		}}}},
		{"custom rule with out-of-range confidence", Config{CustomRules: []CustomRule{{
			ID:         "c1",
			Triggers:   []string{"x"},
			Confidence: Confidence(255), // e.g. Confidence(-1) wrapped through uint8
			Validate:   func([]byte, int, int) (int, int, bool) { return 0, 0, false },
		}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New(%s) error = %v, want ErrInvalidConfig", tc.name, err)
			}
		})
	}
}

func TestProfileStrings(t *testing.T) {
	if ProfileFast.String() != "fast" || ProfileBalanced.String() != "balanced" || ProfileDeep.String() != "deep" {
		t.Error("unexpected profile names")
	}
	if !strings.Contains(Profile(9).String(), "unknown") {
		t.Error("out-of-range profile should stringify as unknown")
	}
}

func TestEngineIsReusable(t *testing.T) {
	e, err := New(Config{CustomRules: []CustomRule{{
		ID:       "test-rule",
		Triggers: []string{"SECRET="},
		Validate: func(w []byte, ts, te int) (int, int, bool) { return ts, te, false },
	}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The same Engine value must be usable for multiple scans; until the
	// streaming engine lands this just checks the compiled set persists.
	if e.rules == nil || len(e.rules.Rules) == 0 {
		t.Fatal("compiled rule set missing")
	}
}
