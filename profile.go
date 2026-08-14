package goredact

// Profile selects a predefined trade-off between scanning throughput and
// detection depth.
type Profile int

const (
	// ProfileFast enables only deterministic, high-confidence detectors:
	// provider token prefixes, authentication headers, credential-bearing
	// URLs, and private-key markers.
	ProfileFast Profile = iota

	// ProfileBalanced is the default. It extends ProfileFast with
	// contextual assignment detection, entropy validation, cookies, and
	// common generic credential patterns.
	ProfileBalanced

	// ProfileDeep extends ProfileBalanced with more expensive or
	// lower-confidence detectors and selected decoding.
	ProfileDeep
)

// String returns the profile name.
func (p Profile) String() string {
	switch p {
	case ProfileFast:
		return "fast"
	case ProfileBalanced:
		return "balanced"
	case ProfileDeep:
		return "deep"
	default:
		return "unknown"
	}
}

func (p Profile) valid() bool {
	return p >= ProfileFast && p <= ProfileDeep
}
