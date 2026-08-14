// Source-control and package-registry credential validators:
// GitHub (OAuth, App, refresh, and fine-grained PAT), GitLab (PAT, runner,
// and deploy tokens), npm, PyPI, and Docker Hub. The classic GitHub PAT
// validator (GitHubPAT, trigger "ghp_") already lives in validators.go and
// is not duplicated here.
//
// These share two shapes:
//
//   - prefix + a fixed-length run of ASCII alphanumeric characters
//     (GitHub OAuth/App/refresh tokens, npm access tokens): see
//     fixedAlnumToken.
//   - prefix + a variable-length run of a wider token alphabet
//     ([A-Za-z0-9_-]) bounded by a min/max length (GitLab PAT/runner/
//     deploy tokens, PyPI API tokens, Docker Hub PATs): see runToken.
//
// GitHubFineGrainedPAT is the one irregular shape (two fixed-length
// alnum runs separated by a literal underscore) and is implemented
// directly.
package validators

import "bytes"

// isTokenChar reports whether c is a valid character in the URL-safe
// token alphabets used by GitLab, PyPI, and Docker Hub credentials: ASCII
// letters, digits, hyphen, and underscore.
func isTokenChar(c byte) bool {
	return isAlnum(c) || c == '-' || c == '_'
}

// consumeRun consumes the maximal run of bytes satisfying pred starting
// at pos and reports the end offset, succeeding only if the run's length
// is within [min, max]. It never indexes out of range.
//
// When the maximal run exceeds max, the whole match is rejected outright;
// no attempt is made to backtrack to a shorter, in-range prefix. A token
// immediately followed by more of its own alphabet is a prefix of
// something longer, not this token — the same convention consumeAlnumRun
// (validators.go) already establishes for the seed validators.
func consumeRun(window []byte, pos, min, max int, pred func(byte) bool) (end int, ok bool) {
	start := pos
	for pos < len(window) && pred(window[pos]) {
		pos++
	}
	n := pos - start
	if n < min || n > max {
		return pos, false
	}
	return pos, true
}

// isXRun reports whether every byte in b is 'x'/'X' or a separator ('-'
// or '_'), with at least one x/X byte present. This catches placeholder
// tokens such as "XXXX-XXXX-XXXX" that allSame alone would miss because
// of the separators.
func isXRun(b []byte) bool {
	sawX := false
	for _, c := range b {
		switch {
		case c == '-' || c == '_':
			// separator, ignore
		case c == 'x' || c == 'X':
			sawX = true
		default:
			return false
		}
	}
	return sawX
}

// asciiEqualFold reports whether a and b are equal under ASCII
// case-folding. It always returns false when the lengths differ.
func asciiEqualFold(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// containsFold reports whether b contains sub, compared under ASCII
// case-folding. An empty sub is trivially contained.
func containsFold(b []byte, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	n := len(b) - len(sub)
	for i := 0; i <= n; i++ {
		if asciiEqualFold(b[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

// isPlaceholder reports whether b looks like a documentation/example
// placeholder rather than a real credential: every byte identical
// (allSame), an x/X run possibly broken up by separators (isXRun), a
// literal ellipsis ("..." or "…"), or the word "example".
func isPlaceholder(b []byte) bool {
	if allSame(b) {
		return true
	}
	if isXRun(b) {
		return true
	}
	if containsFold(b, "example") {
		return true
	}
	if bytes.Contains(b, []byte("...")) || bytes.Contains(b, []byte("…")) {
		return true
	}
	return false
}

// fixedAlnumToken confirms that window[trigEnd:] begins with exactly
// length ASCII alphanumeric characters followed by a non-alphanumeric
// byte (or end of window), and that the body is not a placeholder. It
// backs every source-control token format that is prefix + a
// fixed-length alnum body: GitHub OAuth, App, and refresh tokens, and npm
// access tokens.
func fixedAlnumToken(window []byte, trigStart, trigEnd, length int) (start, end int, ok bool) {
	bodyEnd := trigEnd + length
	if bodyEnd > len(window) {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if !allAlnum(body) {
		return 0, 0, false
	}
	if !boundaryOK(window, bodyEnd) {
		return 0, 0, false
	}
	if isPlaceholder(body) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// runToken confirms that window[trigEnd:] begins with a run of
// [min, max] isTokenChar bytes, and that the body is not a placeholder.
// It backs every token format that is prefix + a variable-length
// token-alphabet body: GitLab PAT/runner/deploy tokens, PyPI API tokens,
// and Docker Hub PATs.
func runToken(window []byte, trigStart, trigEnd, min, max int) (start, end int, ok bool) {
	bodyEnd, ok := consumeRun(window, trigEnd, min, max, isTokenChar)
	if !ok {
		return 0, 0, false
	}
	body := window[trigEnd:bodyEnd]
	if isPlaceholder(body) {
		return 0, 0, false
	}
	return trigStart, bodyEnd, true
}

// GitHubOAuthToken confirms the GitHub OAuth access token shape: trigger
// "gho_" followed by exactly 36 ASCII alphanumeric characters.
//
// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats
func GitHubOAuthToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return fixedAlnumToken(window, trigStart, trigEnd, 36)
}

// GitHubAppToken confirms the GitHub App installation/user-to-server
// token shape: trigger "ghu_" or "ghs_" followed by exactly 36 ASCII
// alphanumeric characters.
//
// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats
func GitHubAppToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return fixedAlnumToken(window, trigStart, trigEnd, 36)
}

// GitHubRefreshToken confirms the GitHub OAuth refresh token shape:
// trigger "ghr_" followed by exactly 36 ASCII alphanumeric characters.
//
// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats
func GitHubRefreshToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return fixedAlnumToken(window, trigStart, trigEnd, 36)
}

// GitHubFineGrainedPAT confirms the GitHub fine-grained personal access
// token shape: trigger "github_pat_" followed by 22 ASCII alphanumeric
// characters, a literal underscore, and 59 more ASCII alphanumeric
// characters.
//
// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats
func GitHubFineGrainedPAT(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	const part1Len = 22
	const part2Len = 59

	part1End := trigEnd + part1Len
	if part1End >= len(window) {
		// Need room for part1 AND the separator byte at part1End.
		return 0, 0, false
	}
	part1 := window[trigEnd:part1End]
	if !allAlnum(part1) {
		return 0, 0, false
	}
	if window[part1End] != '_' {
		return 0, 0, false
	}

	part2Start := part1End + 1
	part2End := part2Start + part2Len
	if part2End > len(window) {
		return 0, 0, false
	}
	part2 := window[part2Start:part2End]
	if !allAlnum(part2) {
		return 0, 0, false
	}
	if !boundaryOK(window, part2End) {
		return 0, 0, false
	}
	if isPlaceholder(part1) || isPlaceholder(part2) {
		return 0, 0, false
	}
	return trigStart, part2End, true
}

// GitLabPAT confirms the GitLab personal access token shape: trigger
// "glpat-" followed by 20-50 characters from [A-Za-z0-9_-].
//
// https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token
func GitLabPAT(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return runToken(window, trigStart, trigEnd, 20, 50)
}

// GitLabRunnerToken confirms the GitLab runner authentication token
// shape: trigger "glrt-" followed by 20-50 characters from
// [A-Za-z0-9_-].
//
// https://docs.gitlab.com/ci/runners/new_creation_workflow/#glrt-authentication-tokens
func GitLabRunnerToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return runToken(window, trigStart, trigEnd, 20, 50)
}

// GitLabDeployToken confirms the GitLab deploy token shape: trigger
// "gldt-" followed by 20-50 characters from [A-Za-z0-9_-].
//
// https://docs.gitlab.com/user/project/deploy_tokens/
func GitLabDeployToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return runToken(window, trigStart, trigEnd, 20, 50)
}

// NpmAccessToken confirms the npm access token shape: trigger "npm_"
// followed by exactly 36 ASCII alphanumeric characters.
//
// The fixed length plus trailing-boundary check are what let this
// trigger safely coexist with npm's own identifier prefixes, e.g.
// "npm_config_registry" or "npm_config_yes": their bodies are not 36
// bytes of pure alphanumerics (an underscore breaks the run well short
// of 36), so fixedAlnumToken rejects them.
//
// https://docs.npmjs.com/about-access-tokens
func NpmAccessToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return fixedAlnumToken(window, trigStart, trigEnd, 36)
}

// PyPIAPIToken confirms the PyPI API token shape: trigger "pypi-"
// followed by 85-300 characters from [A-Za-z0-9_-] (a base64url-encoded
// macaroon). 300 is a generous practical ceiling chosen for this
// validator, not a documented maximum — PyPI does not publish an upper
// bound on token length.
//
// https://docs.pypi.org/api/token/
func PyPIAPIToken(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return runToken(window, trigStart, trigEnd, 85, 300)
}

// DockerHubPAT confirms the Docker Hub personal access token shape:
// trigger "dckr_pat_" followed by 27-100 characters from [A-Za-z0-9_-].
// 100 is a generous practical ceiling chosen for this validator, not a
// documented maximum.
//
// https://docs.docker.com/security/for-developers/access-tokens/
func DockerHubPAT(window []byte, trigStart, trigEnd int) (start, end int, ok bool) {
	return runToken(window, trigStart, trigEnd, 27, 100)
}
