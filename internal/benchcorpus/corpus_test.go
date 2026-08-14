package benchcorpus

import (
	"io"
	"testing"
)

func TestReaderExactAndReproducible(t *testing.T) {
	for _, scenario := range All {
		a, err := Reader(scenario, 1003)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Reader(scenario, 1003)
		if err != nil {
			t.Fatal(err)
		}
		gotA, err := io.ReadAll(a)
		if err != nil {
			t.Fatal(err)
		}
		gotB, err := io.ReadAll(b)
		if err != nil {
			t.Fatal(err)
		}
		if string(gotA) != string(gotB) || len(gotA) != 1003 {
			t.Fatalf("%s: non-reproducible or wrong length: %d/%d", scenario, len(gotA), len(gotB))
		}
	}
}

func TestReaderRejectsInvalidInput(t *testing.T) {
	if _, err := Reader("unknown", 1); err == nil {
		t.Fatal("expected unknown scenario error")
	}
	if _, err := Reader(Quiet, -1); err == nil {
		t.Fatal("expected negative size error")
	}
}
