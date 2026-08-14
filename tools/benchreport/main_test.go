package main

import "testing"

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"100MiB": 100 << 20, "500MiB": 500 << 20, "1GiB": 1 << 30, "7B": 7} {
		got, err := parseSize(in)
		if err != nil || got != want {
			t.Fatalf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := parseSize("100MB"); err == nil {
		t.Fatal("expected invalid unit")
	}
}

func TestCheckBudgets(t *testing.T) {
	r := report{Results: []result{{Scenario: "x", Size: 100, MiBPerSecond: 4, AllocBytes: 30}}}
	if checkBudgets(r, 5, .25) == nil {
		t.Fatal("expected both budgets to fail")
	}
	if err := checkBudgets(r, 4, .30); err != nil {
		t.Fatal(err)
	}
}
