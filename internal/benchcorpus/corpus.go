// Package benchcorpus provides deterministic, allocation-light benchmark
// inputs. Corpora are generated while being read, so the 1 GiB suite does not
// require a 1 GiB fixture in the repository or in memory.
package benchcorpus

import (
	"fmt"
	"io"
)

type Scenario string

const (
	Quiet           Scenario = "quiet"
	KeywordDense    Scenario = "keyword-dense"
	Adversarial     Scenario = "adversarial"
	ConfirmedSecret Scenario = "confirmed-secret"
)

var All = []Scenario{Quiet, KeywordDense, Adversarial, ConfirmedSecret}

// Seed is incremented when the generated corpus changes incompatibly.
const Seed uint64 = 0x4752440000000001

var records = map[Scenario][]byte{
	Quiet:           []byte("{\"time\":\"2026-08-14T12:00:00Z\",\"level\":\"info\",\"method\":\"GET\",\"path\":\"/api/v1/items\",\"status\":200,\"duration_ms\":2.31}\n"),
	KeywordDense:    []byte("token=none authorization=disabled password_policy=strong secret_rotation=complete AKIA-short ghp_short xoxb-1-2 webhook=https://example.invalid/health\n"),
	Adversarial:     []byte("ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX ghp_aaaa ghp_aaaa ghp_aaaa xoxb-0265423511615-5940781618495-aaaaaaaaaaaaaaaaaaaaaaaaaaaa AKIAIOSFODNN7EXAMPLE authorization: bearer short\n"),
	ConfirmedSecret: []byte("{\"github\":\"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\",\"aws_access_key_id\":\"AKIAUJZDEGXDNCF32EPF\",\"event\":\"credential_loaded\"}\n"),
}

// Reader returns exactly size bytes. Every call begins from the same seed and
// byte sequence; chunking by the consumer cannot change the corpus.
func Reader(s Scenario, size int64) (io.Reader, error) {
	record, ok := records[s]
	if !ok {
		return nil, fmt.Errorf("unknown corpus scenario %q", s)
	}
	if size < 0 {
		return nil, fmt.Errorf("negative corpus size %d", size)
	}
	return &reader{record: record, remaining: size}, nil
}

type reader struct {
	record    []byte
	offset    int
	remaining int64
}

func (r *reader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n := len(p)
	for len(p) > 0 {
		copied := copy(p, r.record[r.offset:])
		p = p[copied:]
		r.offset += copied
		if r.offset == len(r.record) {
			r.offset = 0
		}
	}
	r.remaining -= int64(n)
	return n, nil
}
