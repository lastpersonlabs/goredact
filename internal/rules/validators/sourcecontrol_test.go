package validators

import (
	"strings"
	"testing"
)

// validateFunc mirrors rules.ValidateFunc without importing the rules
// package (which would create an import cycle risk and isn't needed for
// unit-testing these functions directly).
type validateFunc func(window []byte, trigStart, trigEnd int) (start, end int, ok bool)

// sourceControlCase is one table-driven test case shared by every
// validator test below.
type sourceControlCase struct {
	name      string
	window    string
	trigStart int
	trigEnd   int
	wantOK    bool
	wantStart int
	wantEnd   int
}

func runSourceControlCases(t *testing.T, fn validateFunc, cases []sourceControlCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := fn([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

// assertNeverPanics runs fn against every truncation of window (from the
// empty slice up to the full window), clamping trigStart/trigEnd into
// range for each truncation, and fails the test if fn ever panics. This
// is the brute-force truncation sweep every fixture window goes through.
func assertNeverPanics(t *testing.T, label string, fn validateFunc, window string, trigStart, trigEnd int) {
	t.Helper()
	for cut := 0; cut <= len(window); cut++ {
		w := window[:cut]
		ts, te := trigStart, trigEnd
		if te > len(w) {
			te = len(w)
		}
		if ts > te {
			ts = te
		}
		if ts < 0 {
			ts = 0
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s(%q, %d, %d) panicked: %v", label, w, ts, te, r)
				}
			}()
			fn([]byte(w), ts, te)
		}()
	}
}

// occurrencesOf returns every start index of trig within data, including
// overlapping ones.
func occurrencesOf(data, trig string) []int {
	var out []int
	for i := 0; i+len(trig) <= len(data); i++ {
		if data[i:i+len(trig)] == trig {
			out = append(out, i)
		}
	}
	return out
}

// sweepFixtures runs assertNeverPanics for every occurrence of trig in
// every fixture window, across match and nomatch alike: panics matter
// regardless of which bucket a fixture is in.
func sweepFixtures(t *testing.T, label string, fn validateFunc, trig string, fixtures []string) {
	t.Helper()
	for _, fx := range fixtures {
		for _, idx := range occurrencesOf(fx, trig) {
			assertNeverPanics(t, label, fn, fx, idx, idx+len(trig))
		}
	}
}

const (
	oauth36a    = "L2m69I7wDdQGnMo6sFSYnvCeqmkfCXIxmEYu"
	oauth36b    = "jRNwkJTQMlysNBKLcUHINVH44lVYyCoGifZd"
	appGhu36a   = "TD7USV0nSe6MVhPyD4v3RhFfioL0bco9gSiM"
	appGhs36a   = "9b3mUXozvaTiZ0b6kg5jhePWvxPd3mLqzu8N"
	refresh36a  = "4LwLYg8atHXKvsk2wkW4jgQzw7k2BNy1DF43"
	refresh36b  = "T5EbJ8H0Ed9ZqZemZFxBCVPsSoVDrTEPilrx"
	fgpatP1a    = "pNLXUQBEWt9iBIWhqsMcTQ"
	fgpatP2a    = "iT0f4QyUrymftnlmT2umhmf7J6BgIuQ3ynO4SNP6dVUK0CcwZUvP8pmGW9F"
	fgpatP1b    = "roDCJdgoGF9tK6HfYpCGrB"
	fgpatP2b    = "7yY0MpAETrOISeIAGuVch0G6fjCOaH5B8LYQorsxxGgA7JX4Dr65R4imqAE"
	glPat30a    = "BO_yY1vy1Dx71XJWCS_eOE50i2nLmR"
	glPat25b    = "9M71uUC6dXE67HSyDv5S0ZGci"
	glRunner28a = "dJc9SE3diMqM_KM3RYy7XNeTwCI_"
	glRunner22b = "EmRFgtLiVRnl7YoMV36D9C"
	glDeploy35a = "KzooQLKR9hstfKw-FvxsBs2bzQFJDG0Vy9R"
	glDeploy20b = "Mbpq99FJ02j5iOP_hnZ4"
	npm36a      = "plknz1kJAShTH8KvwDZPcixBekByPBAakTBO"
	npm36b      = "TOltgSxsXbtv4bMFG9MvKZHj0LRUG1a6nKiZ"
	pypi100a    = "Kx3nk2FwGJA8cZG3hRAq7b_1nfEB9W8xiavowuP8SWVADE1tXNac50deIoGvPKXvSt3lTrHxfFid0utBAisqoF_I6b6SFx4fDBmH"
	pypi90b     = "Fy7lOBCGPVunOMqKKLByo2Azdma5XY3XWladYTLBrX1P9HS2JJWJTgPCEQQLtkaREmFr1hs7k7dnztUQC9AsSxYc1x"
	dh36a       = "lBYwwQKx2h3qd82R5DtSx3oPE2-xPo0csQ6U"
	dh28b       = "BMjUC6unM5EYWsQJ8jXp5k_KVfOY"

	glft20a     = "XJJLCZ04E6yueXEpQefR"
	glft20b     = "UFYyyRawWqeAbaVXuUJi"
	glft19      = "CLxhv_NHIVx5KNI_UW2"
	glftV2Hex64 = "84f112654236471bc18d24d00cc1b55ad8709046ed3c988085de23eb6b7b4469"
	glftV2Hex63 = "a8a7265ce15ed1f17a28be7a987bbf95072249af09390f98be90c4aa3abca51"
	glptt40a    = "wz8oguT2oAIeK7BCnbcsxaRzaDNf1V9R35VCfS64"
	glptt40b    = "oJWqsIdbQqt_0d6eu2-isgybGn4CIag0ZUG0CCle"
	glptt39     = "uInZw-iAVKG_KZwOLJnaESEbVBaCCuwZQ_9FMrZ"
	dhOat32a    = "O2TPoiMQpBYgkeZsuy1X65fLTSjef12C"
	dhOat100    = "jkzcAlm3lER4Bs673LUvfiPd4SyTffGfLn0b5h3PgIkppkDbSF9b6h4EPT2cRr9crtNjcpByF2TgMaJoSbm_1hukVDRIU3j9VmHP"
	dhOat31     = "HnKtVesHHO-mmpkvxro6pmOrrFZ6a0w"
)

func TestGitHubOAuthToken(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "gho_" + oauth36a,
			trigStart: 0, trigEnd: 4,
			wantOK: true, wantStart: 0, wantEnd: 4 + 36,
		},
		{
			name:      "token ends exactly at window end",
			window:    "prefix gho_" + oauth36b,
			trigStart: 7, trigEnd: 11,
			wantOK: true, wantStart: 7, wantEnd: 11 + 36,
		},
		{
			name:      "non-alnum boundary accepted",
			window:    "gho_" + oauth36a + ".",
			trigStart: 0, trigEnd: 4,
			wantOK: true, wantStart: 0, wantEnd: 4 + 36,
		},
		{
			name:      "alnum boundary violation rejected",
			window:    "gho_" + oauth36a + "Z",
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "wrong length (too short)",
			window:    "gho_tooShort123",
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "gho_" + string(makeN('X', 36)),
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "truncated window returns false",
			window:    "gho_" + oauth36a[:10],
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "trigger at very end of window, zero bytes follow",
			window:    "gho_",
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
	}
	runSourceControlCases(t, GitHubOAuthToken, cases)
}

func TestGitHubOAuthTokenNeverPanics(t *testing.T) {
	fixtures := []string{
		"GITHUB_OAUTH_TOKEN=gho_" + oauth36a,
		`{"access_token": "gho_` + oauth36b + `", "token_type": "bearer"}`,
		"GITHUB_OAUTH_TOKEN=gho_tooShort123",
		"GITHUB_OAUTH_TOKEN=gho_" + string(makeN('X', 36)),
		"GITHUB_OAUTH_TOKEN=gho_" + oauth36a[:20] + " " + oauth36a[20:],
		"", "gho_", "gho_a",
	}
	sweepFixtures(t, "GitHubOAuthToken", GitHubOAuthToken, "gho_", fixtures)
}

func TestGitHubAppToken(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "ghu_ trigger match at window start",
			window:    "ghu_" + appGhu36a,
			trigStart: 0, trigEnd: 4,
			wantOK: true, wantStart: 0, wantEnd: 4 + 36,
		},
		{
			name:      "ghs_ trigger, token ends exactly at window end",
			window:    "installation_token: ghs_" + appGhs36a,
			trigStart: 20, trigEnd: 24,
			wantOK: true, wantStart: 20, wantEnd: 24 + 36,
		},
		{
			name:      "wrong length",
			window:    "ghu_tooShort",
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "ghs_" + string(makeN('X', 36)),
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "boundary violation (extra alnum byte)",
			window:    "ghu_" + appGhu36a + "1",
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "truncated window returns false",
			window:    "ghu_" + appGhu36a[:5],
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
	}
	runSourceControlCases(t, GitHubAppToken, cases)
}

func TestGitHubAppTokenNeverPanics(t *testing.T) {
	fixtures := []string{
		"GITHUB_APP_USER_TOKEN=ghu_" + appGhu36a,
		"installation_token: ghs_" + appGhs36a,
		"ghu_tooShort",
		"ghs_" + string(makeN('X', 36)),
		"ghu_" + appGhu36a + "1",
		"", "ghu_", "ghs_", "ghu_a",
	}
	sweepFixtures(t, "GitHubAppToken/ghu_", GitHubAppToken, "ghu_", fixtures)
	sweepFixtures(t, "GitHubAppToken/ghs_", GitHubAppToken, "ghs_", fixtures)
}

func TestGitHubRefreshToken(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "ghr_" + refresh36a,
			trigStart: 0, trigEnd: 4,
			wantOK: true, wantStart: 0, wantEnd: 4 + 36,
		},
		{
			name:      "token ends exactly at window end",
			window:    `{"refresh_token":"ghr_` + refresh36b + `"}`,
			trigStart: 18, trigEnd: 22,
			wantOK: true, wantStart: 18, wantEnd: 22 + 36,
		},
		{
			name:      "wrong length",
			window:    "ghr_short",
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "ghr_" + string(makeN('X', 36)),
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "wrong alphabet breaks run short",
			window:    "ghr_" + refresh36a[:18] + " " + refresh36a[18:],
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "truncated window returns false",
			window:    "ghr_" + refresh36a[:30],
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
	}
	runSourceControlCases(t, GitHubRefreshToken, cases)
}

func TestGitHubRefreshTokenNeverPanics(t *testing.T) {
	fixtures := []string{
		"GITHUB_REFRESH_TOKEN=ghr_" + refresh36a,
		`{"refresh_token":"ghr_` + refresh36b + `"}`,
		"GITHUB_REFRESH_TOKEN=ghr_short",
		"GITHUB_REFRESH_TOKEN=ghr_" + string(makeN('X', 36)),
		"GITHUB_REFRESH_TOKEN=ghr_" + refresh36a[:18] + " " + refresh36a[18:],
		"", "ghr_", "ghr_a",
	}
	sweepFixtures(t, "GitHubRefreshToken", GitHubRefreshToken, "ghr_", fixtures)
}

func TestGitHubFineGrainedPAT(t *testing.T) {
	full := fgpatP1a + "_" + fgpatP2a
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "github_pat_" + full,
			trigStart: 0, trigEnd: 11,
			wantOK: true, wantStart: 0, wantEnd: 11 + len(full),
		},
		{
			name:      "token ends exactly at window end",
			window:    "export TOKEN=github_pat_" + fgpatP1b + "_" + fgpatP2b,
			trigStart: 13, trigEnd: 24,
			wantOK: true, wantStart: 13, wantEnd: 24 + len(fgpatP1b) + 1 + len(fgpatP2b),
		},
		{
			name:      "wrong length (second segment too short)",
			window:    "github_pat_" + fgpatP1a + "_short",
			trigStart: 0, trigEnd: 11,
			wantOK: false,
		},
		{
			name:      "wrong separator (hyphen instead of underscore)",
			window:    "github_pat_" + fgpatP1a + "-" + fgpatP2a,
			trigStart: 0, trigEnd: 11,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "github_pat_" + string(makeN('x', 22)) + "_" + string(makeN('X', 59)),
			trigStart: 0, trigEnd: 11,
			wantOK: false,
		},
		{
			name:      "boundary violation (extra alnum byte)",
			window:    "github_pat_" + full + "9",
			trigStart: 0, trigEnd: 11,
			wantOK: false,
		},
		{
			name:      "truncated window returns false",
			window:    "github_pat_" + fgpatP1a,
			trigStart: 0, trigEnd: 11,
			wantOK: false,
		},
		{
			name:      "no room for separator byte",
			window:    "github_pat_" + fgpatP1a[:21],
			trigStart: 0, trigEnd: 11,
			wantOK: false,
		},
	}
	runSourceControlCases(t, GitHubFineGrainedPAT, cases)
}

func TestGitHubFineGrainedPATNeverPanics(t *testing.T) {
	fixtures := []string{
		"GITHUB_FINE_GRAINED_PAT=github_pat_" + fgpatP1a + "_" + fgpatP2a,
		`export TOKEN="github_pat_` + fgpatP1b + "_" + fgpatP2b + `"`,
		"github_pat_" + fgpatP1a + "_short",
		"github_pat_" + fgpatP1a + "-" + fgpatP2a,
		"github_pat_" + string(makeN('x', 22)) + "_" + string(makeN('X', 59)),
		"", "github_pat_", "github_pat_a",
	}
	sweepFixtures(t, "GitHubFineGrainedPAT", GitHubFineGrainedPAT, "github_pat_", fixtures)
}

func TestGitLabPAT(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "glpat-" + glPat30a,
			trigStart: 0, trigEnd: 6,
			wantOK: true, wantStart: 0, wantEnd: 6 + len(glPat30a),
		},
		{
			name:      "token ends exactly at window end (min length)",
			window:    "Authorization: Bearer glpat-" + glPat25b,
			trigStart: 22, trigEnd: 28,
			wantOK: true, wantStart: 22, wantEnd: 28 + len(glPat25b),
		},
		{
			name:      "too short",
			window:    "glpat-abc123",
			trigStart: 0, trigEnd: 6,
			wantOK: false,
		},
		{
			name:      "broken alphabet (space) below min length",
			window:    "glpat-abcDE12345 " + glPat30a,
			trigStart: 0, trigEnd: 6,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "glpat-" + string(makeN('X', 30)),
			trigStart: 0, trigEnd: 6,
			wantOK: false,
		},
		{
			name:      "truncated window returns false",
			window:    "glpat-" + glPat30a[:10],
			trigStart: 0, trigEnd: 6,
			wantOK: false,
		},
	}
	runSourceControlCases(t, GitLabPAT, cases)
}

func TestGitLabPATNeverPanics(t *testing.T) {
	fixtures := []string{
		"GITLAB_PAT=glpat-" + glPat30a,
		"Authorization: Bearer glpat-" + glPat25b,
		"glpat-abc123",
		"glpat-abcDE12345 " + glPat30a,
		"glpat-" + string(makeN('X', 30)),
		"", "glpat-", "glpat-a",
	}
	sweepFixtures(t, "GitLabPAT", GitLabPAT, "glpat-", fixtures)
}

func TestGitLabRunnerToken(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "glrt-" + glRunner28a,
			trigStart: 0, trigEnd: 5,
			wantOK: true, wantStart: 0, wantEnd: 5 + len(glRunner28a),
		},
		{
			name:      "token ends exactly at window end (min length)",
			window:    `{"token": "glrt-` + glRunner22b + `"}`,
			trigStart: 11, trigEnd: 16,
			wantOK: true, wantStart: 11, wantEnd: 16 + len(glRunner22b),
		},
		{
			name:      "too short",
			window:    "glrt-short1",
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "broken alphabet (space) below min length",
			window:    "glrt-abcDE12345 " + glRunner28a,
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "glrt-" + string(makeN('X', 28)),
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "truncated window returns false",
			window:    "glrt-" + glRunner28a[:8],
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
	}
	runSourceControlCases(t, GitLabRunnerToken, cases)
}

func TestGitLabRunnerTokenNeverPanics(t *testing.T) {
	fixtures := []string{
		"CI_RUNNER_TOKEN=glrt-" + glRunner28a,
		`{"token": "glrt-` + glRunner22b + `"}`,
		"glrt-short1",
		"glrt-abcDE12345 " + glRunner28a,
		"glrt-" + string(makeN('X', 28)),
		"", "glrt-", "glrt-a",
	}
	sweepFixtures(t, "GitLabRunnerToken", GitLabRunnerToken, "glrt-", fixtures)
}

func TestGitLabDeployToken(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "gldt-" + glDeploy35a,
			trigStart: 0, trigEnd: 5,
			wantOK: true, wantStart: 0, wantEnd: 5 + len(glDeploy35a),
		},
		{
			name:      "token ends exactly at window end (min length)",
			window:    "docker login -u deploy -p gldt-" + glDeploy20b,
			trigStart: 26, trigEnd: 31,
			wantOK: true, wantStart: 26, wantEnd: 31 + len(glDeploy20b),
		},
		{
			name:      "too short",
			window:    "gldt-tiny1",
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "broken alphabet (space) below min length",
			window:    "gldt-abcDE12345 " + glDeploy35a,
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "gldt-" + string(makeN('X', 30)),
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "truncated window returns false",
			window:    "gldt-" + glDeploy35a[:10],
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
	}
	runSourceControlCases(t, GitLabDeployToken, cases)
}

func TestGitLabDeployTokenNeverPanics(t *testing.T) {
	fixtures := []string{
		"DEPLOY_TOKEN=gldt-" + glDeploy35a,
		"docker login registry.example.com -u deploy -p gldt-" + glDeploy20b,
		"gldt-tiny1",
		"gldt-abcDE12345 " + glDeploy35a,
		"gldt-" + string(makeN('X', 30)),
		"", "gldt-", "gldt-a",
	}
	sweepFixtures(t, "GitLabDeployToken", GitLabDeployToken, "gldt-", fixtures)
}

func TestNpmAccessToken(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "npm_" + npm36a,
			trigStart: 0, trigEnd: 4,
			wantOK: true, wantStart: 0, wantEnd: 4 + 36,
		},
		{
			name:      "token ends exactly at window end",
			window:    "//registry.npmjs.org/:_authToken=npm_" + npm36b,
			trigStart: 33, trigEnd: 37,
			wantOK: true, wantStart: 33, wantEnd: 37 + 36,
		},
		{
			name:      "identifier collision: npm_config_registry",
			window:    "npm_config_registry=https://registry.npmjs.org/",
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "identifier collision: npm_config_yes",
			window:    "npm_config_yes=true",
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "npm_" + string(makeN('X', 36)),
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "wrong length (too short)",
			window:    "npm_short",
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
		{
			name:      "truncated window returns false",
			window:    "npm_" + npm36a[:10],
			trigStart: 0, trigEnd: 4,
			wantOK: false,
		},
	}
	runSourceControlCases(t, NpmAccessToken, cases)
}

func TestNpmAccessTokenNeverPanics(t *testing.T) {
	fixtures := []string{
		"NPM_TOKEN=npm_" + npm36a,
		"//registry.npmjs.org/:_authToken=npm_" + npm36b,
		"npm_config_registry=https://registry.npmjs.org/",
		"npm_config_yes=true",
		"NPM_TOKEN=npm_" + string(makeN('X', 36)),
		"NPM_TOKEN=npm_short",
		"", "npm_", "npm_a",
	}
	sweepFixtures(t, "NpmAccessToken", NpmAccessToken, "npm_", fixtures)
}

func TestPyPIAPIToken(t *testing.T) {
	infix := "AgEIcHlwaS5vcmc" + "ciP1aKP8I598r9hDBybMnEIx9dj0L-mNSWyd04f1Ibz0rFbGOnIRyMex-3LajVwjAeU-5aeC_7TS"
	cases := []sourceControlCase{
		{
			name:      "match at window start with macaroon infix",
			window:    "pypi-" + infix,
			trigStart: 0, trigEnd: 5,
			wantOK: true, wantStart: 0, wantEnd: 5 + len(infix),
		},
		{
			name:      "token ends exactly at window end (min length)",
			window:    "PYPI_API_TOKEN=pypi-" + pypi90b,
			trigStart: 15, trigEnd: 20,
			wantOK: true, wantStart: 15, wantEnd: 20 + len(pypi90b),
		},
		{
			name:      "too short",
			window:    "pypi-tooShortToken1234567890",
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "broken alphabet (space) below min length",
			window:    "pypi-abcDE12345 " + pypi90b,
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "pypi-" + string(makeN('X', 90)),
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "truncated window returns false",
			window:    "pypi-" + pypi90b[:40],
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
	}
	runSourceControlCases(t, PyPIAPIToken, cases)
}

func TestPyPIAPITokenNeverPanics(t *testing.T) {
	infix := "AgEIcHlwaS5vcmc" + "ciP1aKP8I598r9hDBybMnEIx9dj0L-mNSWyd04f1Ibz0rFbGOnIRyMex-3LajVwjAeU-5aeC_7TS"
	fixtures := []string{
		"PYPI_API_TOKEN=pypi-" + infix,
		"twine upload --repository pypi --password pypi-" + pypi100a + " dist/*",
		"pypi-tooShortToken1234567890",
		"pypi-abcDE12345 " + pypi90b,
		"pypi-" + string(makeN('X', 90)),
		"", "pypi-", "pypi-a",
	}
	sweepFixtures(t, "PyPIAPIToken", PyPIAPIToken, "pypi-", fixtures)
}

func TestDockerHubPAT(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "dckr_pat_" + dh36a,
			trigStart: 0, trigEnd: 9,
			wantOK: true, wantStart: 0, wantEnd: 9 + len(dh36a),
		},
		{
			name:      "token ends exactly at window end (min length)",
			window:    `{"password": "dckr_pat_` + dh28b + `"}`,
			trigStart: 14, trigEnd: 23,
			wantOK: true, wantStart: 14, wantEnd: 23 + len(dh28b),
		},
		{
			name:      "too short",
			window:    "dckr_pat_short12345",
			trigStart: 0, trigEnd: 9,
			wantOK: false,
		},
		{
			name:      "broken alphabet (space) below min length",
			window:    "dckr_pat_abcDE12345 " + dh36a,
			trigStart: 0, trigEnd: 9,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "dckr_pat_" + string(makeN('X', 30)),
			trigStart: 0, trigEnd: 9,
			wantOK: false,
		},
		{
			name:      "truncated window returns false",
			window:    "dckr_pat_" + dh36a[:10],
			trigStart: 0, trigEnd: 9,
			wantOK: false,
		},
	}
	runSourceControlCases(t, DockerHubPAT, cases)
}

func TestDockerHubPATNeverPanics(t *testing.T) {
	fixtures := []string{
		"DOCKERHUB_PAT=dckr_pat_" + dh36a,
		`{"password": "dckr_pat_` + dh28b + `"}`,
		"dckr_pat_short12345",
		"dckr_pat_abcDE12345 " + dh36a,
		"dckr_pat_" + string(makeN('X', 30)),
		"", "dckr_pat_", "dckr_pat_a",
	}
	sweepFixtures(t, "DockerHubPAT", DockerHubPAT, "dckr_pat_", fixtures)
}

func TestGitLabFeedToken(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "glft-" + glft20a,
			trigStart: 0, trigEnd: 5,
			wantOK: true, wantStart: 0, wantEnd: 5 + 20,
		},
		{
			name:      "match with surrounding context",
			window:    "feed_token=glft-" + glft20b,
			trigStart: 11, trigEnd: 16,
			wantOK: true, wantStart: 11, wantEnd: 16 + 20,
		},
		{
			name:      "too short rejected",
			window:    "glft-" + glft19,
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "glft-" + string(makeN('X', 20)),
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "a real v2 token's first 20 bytes are not confirmed by v1",
			window:    "glft-" + glftV2Hex64 + "-12345678",
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "trigger at very end of window",
			window:    "glft-",
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
	}
	runSourceControlCases(t, GitLabFeedToken, cases)
}

func TestGitLabFeedTokenNeverPanics(t *testing.T) {
	fixtures := []string{
		"feed_token=glft-" + glft20a,
		"glft-" + glft19,
		"glft-" + string(makeN('X', 20)),
		"glft-" + glftV2Hex64 + "-12345678",
		"", "glft-", "glft-a",
	}
	sweepFixtures(t, "GitLabFeedToken", GitLabFeedToken, "glft-", fixtures)
}

func TestGitLabFeedTokenV2(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "glft-" + glftV2Hex64 + "-12345678",
			trigStart: 0, trigEnd: 5,
			wantOK: true, wantStart: 0, wantEnd: 5 + 64 + 1 + 8,
		},
		{
			name:      "match with surrounding context, single-digit user id",
			window:    "feed_token=glft-" + glftV2Hex64 + "-1",
			trigStart: 11, trigEnd: 16,
			wantOK: true, wantStart: 11, wantEnd: 16 + 64 + 1 + 1,
		},
		{
			name:      "uppercase hex accepted",
			window:    "glft-" + strings.ToUpper(glftV2Hex64) + "-42",
			trigStart: 0, trigEnd: 5,
			wantOK: true, wantStart: 0, wantEnd: 5 + 64 + 1 + 2,
		},
		{
			name:      "63-char hex (one short) rejected",
			window:    "glft-" + glftV2Hex63 + "-12345678",
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "missing dash separator rejected",
			window:    "glft-" + glftV2Hex64 + "12345678",
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "no digits after dash rejected",
			window:    "glft-" + glftV2Hex64 + "-",
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "a real v1 token is not confirmed by v2",
			window:    "glft-" + glft20a,
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "placeholder hex rejected",
			window:    "glft-" + string(makeN('a', 64)) + "-12345678",
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
		{
			name:      "trigger at very end of window",
			window:    "glft-",
			trigStart: 0, trigEnd: 5,
			wantOK: false,
		},
	}
	runSourceControlCases(t, GitLabFeedTokenV2, cases)
}

func TestGitLabFeedTokenV2NeverPanics(t *testing.T) {
	fixtures := []string{
		"feed_token=glft-" + glftV2Hex64 + "-12345678",
		"glft-" + glftV2Hex63 + "-12345678",
		"glft-" + glftV2Hex64 + "12345678",
		"glft-" + glftV2Hex64 + "-",
		"glft-" + glft20a,
		"", "glft-", "glft-a",
	}
	sweepFixtures(t, "GitLabFeedTokenV2", GitLabFeedTokenV2, "glft-", fixtures)
}

func TestGitLabPipelineTriggerToken(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match at window start",
			window:    "glptt-" + glptt40a,
			trigStart: 0, trigEnd: 6,
			wantOK: true, wantStart: 0, wantEnd: 6 + 40,
		},
		{
			name:      "match with surrounding context",
			window:    "token=glptt-" + glptt40b,
			trigStart: 6, trigEnd: 12,
			wantOK: true, wantStart: 6, wantEnd: 12 + 40,
		},
		{
			name:      "too short rejected",
			window:    "glptt-" + glptt39,
			trigStart: 0, trigEnd: 6,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "glptt-" + string(makeN('X', 40)),
			trigStart: 0, trigEnd: 6,
			wantOK: false,
		},
		{
			name:      "trigger at very end of window",
			window:    "glptt-",
			trigStart: 0, trigEnd: 6,
			wantOK: false,
		},
	}
	runSourceControlCases(t, GitLabPipelineTriggerToken, cases)
}

func TestGitLabPipelineTriggerTokenNeverPanics(t *testing.T) {
	fixtures := []string{
		"token=glptt-" + glptt40a,
		"glptt-" + glptt39,
		"glptt-" + string(makeN('X', 40)),
		"", "glptt-", "glptt-a",
	}
	sweepFixtures(t, "GitLabPipelineTriggerToken", GitLabPipelineTriggerToken, "glptt-", fixtures)
}

func TestDockerHubOAT(t *testing.T) {
	cases := []sourceControlCase{
		{
			name:      "match, min length (32 chars)",
			window:    "dckr_oat_" + dhOat32a,
			trigStart: 0, trigEnd: 9,
			wantOK: true, wantStart: 0, wantEnd: 9 + len(dhOat32a),
		},
		{
			name:      "match, generous length (100 chars)",
			window:    `{"password": "dckr_oat_` + dhOat100 + `"}`,
			trigStart: 14, trigEnd: 23,
			wantOK: true, wantStart: 14, wantEnd: 23 + len(dhOat100),
		},
		{
			name:      "31 chars (one short of the personal-token-derived floor) rejected",
			window:    "dckr_oat_" + dhOat31,
			trigStart: 0, trigEnd: 9,
			wantOK: false,
		},
		{
			name:      "placeholder rejected",
			window:    "dckr_oat_" + string(makeN('X', 32)),
			trigStart: 0, trigEnd: 9,
			wantOK: false,
		},
		{
			name:      "trigger at very end of window",
			window:    "dckr_oat_",
			trigStart: 0, trigEnd: 9,
			wantOK: false,
		},
	}
	runSourceControlCases(t, DockerHubOAT, cases)
}

func TestDockerHubOATNeverPanics(t *testing.T) {
	fixtures := []string{
		"DOCKERHUB_OAT=dckr_oat_" + dhOat32a,
		`{"password": "dckr_oat_` + dhOat100 + `"}`,
		"dckr_oat_" + dhOat31,
		"dckr_oat_" + string(makeN('X', 32)),
		"", "dckr_oat_", "dckr_oat_a",
	}
	sweepFixtures(t, "DockerHubOAT", DockerHubOAT, "dckr_oat_", fixtures)
}

func TestSourceControlHelpers(t *testing.T) {
	if !isTokenChar('-') || !isTokenChar('_') || !isTokenChar('a') || !isTokenChar('9') {
		t.Error("isTokenChar rejected a valid token character")
	}
	if isTokenChar('!') || isTokenChar(' ') {
		t.Error("isTokenChar accepted an invalid token character")
	}
	if !isXRun([]byte("XXXX-XXXX-XXXX")) {
		t.Error(`isXRun("XXXX-XXXX-XXXX") = false, want true`)
	}
	if !isXRun([]byte("xxxxxxxx")) {
		t.Error(`isXRun("xxxxxxxx") = false, want true`)
	}
	if isXRun([]byte("--__")) {
		t.Error(`isXRun("--__") = true, want false (no x at all)`)
	}
	if isXRun([]byte("xxxAxxx")) {
		t.Error(`isXRun("xxxAxxx") = true, want false`)
	}
	if !containsFold([]byte("my-EXAMPLE-token"), "example") {
		t.Error(`containsFold(..., "example") = false, want true`)
	}
	if containsFold([]byte("realtoken"), "example") {
		t.Error(`containsFold("realtoken", "example") = true, want false`)
	}
	if !isPlaceholder([]byte("xxxxxxxxxxxxxxxxxxxx")) {
		t.Error("isPlaceholder did not flag an all-x run")
	}
	if !isPlaceholder([]byte("token-example-value1")) {
		t.Error(`isPlaceholder did not flag a body containing "example"`)
	}
	if isPlaceholder([]byte(oauth36a)) {
		t.Error("isPlaceholder incorrectly flagged a realistic random token")
	}
	if end, ok := consumeRun([]byte("abc!def"), 0, 3, 3, isTokenChar); !ok || end != 3 {
		t.Errorf("consumeRun exact-length case = (%d, %v), want (3, true)", end, ok)
	}
	if _, ok := consumeRun([]byte("abc-def"), 0, 10, 20, isTokenChar); ok {
		t.Error("consumeRun accepted a run shorter than min")
	}
}
