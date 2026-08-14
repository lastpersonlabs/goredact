package goredact

import core "github.com/lastpersonlabs/goredact/internal/goredact"

// Public types are aliases to the implementation package. Aliasing keeps the
// module-root API stable while allowing the implementation to live outside the
// repository root.
type (
	Config       = core.Config
	CustomRule   = core.CustomRule
	Engine       = core.Engine
	Profile      = core.Profile
	Confidence   = core.Confidence
	MaskStrategy = core.MaskStrategy
	Finding      = core.Finding
	Stats        = core.Stats
	RuleInfo     = core.RuleInfo
	ReadError    = core.ReadError
	WriteError   = core.WriteError
)

const (
	DefaultChunkSize = core.DefaultChunkSize
	DefaultMarker    = core.DefaultMarker

	ProfileFast     = core.ProfileFast
	ProfileBalanced = core.ProfileBalanced
	ProfileDeep     = core.ProfileDeep

	ConfidenceLow    = core.ConfidenceLow
	ConfidenceMedium = core.ConfidenceMedium
	ConfidenceHigh   = core.ConfidenceHigh

	MaskFixedMarker      = core.MaskFixedMarker
	MaskLengthPreserving = core.MaskLengthPreserving
	MaskFormatPreserving = core.MaskFormatPreserving
)

var ErrInvalidConfig = core.ErrInvalidConfig

// New constructs a reusable secret-redaction engine.
func New(cfg Config) (*Engine, error) {
	return core.New(cfg)
}

// BuiltinRules returns every built-in rule shipped by this version.
func BuiltinRules() []RuleInfo {
	return core.BuiltinRules()
}
