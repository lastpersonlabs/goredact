package goredact

// Profile selects a predefined trade-off between scanning throughput and
// detection depth.
type Profile int

const (
	// profileUnspecified is the zero value of Profile. It is not a
	// selectable profile: reserving it lets New distinguish an unset
	// Config.Profile (the zero value of Config) from an explicit choice
	// of ProfileFast, so New(Config{}) can default to ProfileBalanced as
	// documented instead of silently running ProfileFast.
	profileUnspecified Profile = iota

	// ProfileFast enables only deterministic, high-confidence detectors:
	// provider token prefixes, authentication headers, credential-bearing
	// URLs, and private-key markers.
	ProfileFast

	// ProfileBalanced is the default. It extends ProfileFast with
	// contextual assignment detection, entropy validation, cookies, and
	// common generic credential patterns.
	ProfileBalanced

	// ProfileDeep extends ProfileBalanced with more expensive or
	// lower-confidence detectors and selected decoding. In v0.1 no
	// built-in rule is deep-only: ProfileDeep and ProfileBalanced select
	// the identical rule set. See docs/PROFILES.md.
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
