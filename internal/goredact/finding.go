package goredact

// Confidence expresses how certain a rule is that a match is a real secret.
type Confidence int

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

// String returns the confidence name.
func (c Confidence) String() string {
	switch c {
	case ConfidenceLow:
		return "low"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	default:
		return "unknown"
	}
}

// Finding describes one confirmed and redacted secret occurrence.
//
// A Finding never contains the matched secret value, only its location and
// the rule that confirmed it. Offsets refer to byte positions in the
// original (unredacted) input stream.
type Finding struct {
	// RuleID is the stable identifier of the rule that confirmed the
	// secret, e.g. "aws-access-key-id".
	RuleID string

	// Confidence is the confidence level of the confirming rule.
	Confidence Confidence

	// Start is the byte offset of the first redacted byte in the input.
	Start int64

	// End is the byte offset one past the last redacted byte in the input.
	End int64
}

// Stats summarises one Redact call. It never contains matched input bytes.
type Stats struct {
	// BytesRead is the total number of input bytes consumed.
	BytesRead int64

	// BytesWritten is the total number of output bytes produced.
	BytesWritten int64

	// Candidates is the number of trigger/rule pairs submitted to a
	// validator. It is useful for operational and benchmark telemetry and
	// never exposes input contents.
	Candidates int64

	// Findings is the number of confirmed, redacted secret spans.
	Findings int64

	// RedactedBytes is the total number of input bytes replaced by
	// redaction markers.
	RedactedBytes int64

	// ByRule maps rule IDs to the number of confirmed findings attributed
	// to that rule. It is nil when there are no findings.
	ByRule map[string]int64
}
