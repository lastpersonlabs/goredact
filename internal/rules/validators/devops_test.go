package validators

import "testing"

// Synthetic fixture bodies for the devops.go validators. Never derived
// from real credentials.
const (
	circleciUUIDMin20 = "ZmNeCKCJUqwTJiywtDid"
	circleciUUIDMax24 = "ydm7RQFdqnHvsGVciGyYcFKn"
	circleciHex40     = "b402c80b48ebe56e2d187447683752e8be7cb7c6"

	buildkiteHex40 = "1c49434fc9fd33bbbc7a692df5273261b76946c6"
	buildkiteHex39 = "034919f14b59f96c4ed21114ce156fe7e92a507"

	datadogAPIKey32 = "f79bed8dc074638954ad92d162ec8b47"
	datadogAppKey40 = "c895e80be90a1415abc40bcf062a911170fef922"

	grafanaSABody32    = "JiFENZLNPZmXKleOsSbqy7kbAB9jaVSN"
	grafanaSAChecksum8 = "3219b7f2"

	grafanaGLCBody32  = "tzmWX9AOuI+AOsOnnl6heiMCigW+5DKr"
	grafanaGLCBody400 = "Qn2zsKKiDR7BBiVscQCUhF0+/X9eMiN88mUWHJUBJqFoE71GkiUIzN6gvLa2T6CGStKdT2lce7iydAs8fG8MiUJFS1yEQzz95xj75turLv2vIar71w/y8HJDP3rSJHQKQfBccMD5EJk6e734hTF29j+CFm2LKOKP1y5DOFcG82fkqrh2fOuDAJSVJ3AjYUD73bo5xVI5abSZhGHYoYK3Fh5ufwQS9nlqX28mGt5Y13OYPmcfCTV08LQvAG8yBdDW4Th09RALg5nunfOdgHQhWrBwKSEWUzvwzl/VlYJY3EkXXbuGHtXg48LNEmiPNhL0eLJHcLFcFG21bfxQvAkByL1xTSd4SqEuSsirVE6PiJMadJJIjRkr9f4qtCQHM4065jFVD8xLpXmIm4NC"
	grafanaGLCBody31  = "q5ERnbEyzrrUm9CI//4DA9ubhBA7IaT"

	dopplerBody40 = "RNt5MCGPDZ1b2cHg8vx6sfXQafHksjY3MMtqDJ0Z"
	dopplerBody44 = "RpwELCnrFb98oWDumML7DNJTRzYXqjrVkg4DR3T9QLtf"
	dopplerBody39 = "z8zDjT8CNEWcQRS1MFdPHZQPzt0mCNkPFbY2w2y"
	dopplerBody45 = "SjDIuYrE2R7xCtPmLXnTva41yOKOVTXTOtxcEQMjFNcQ6"

	vercelBody40 = "SQfiU2UPGYQFgbRH10i3tFe4ctqZCCJSmBykIBnh"
	vercelBody80 = "rRFjdIX8lUkowYB8yfkAYB8RYtbSvW2HX4U4n03kDjWVXHUkJoy1spNg6CCzhsFZibOuwF5JWgFuOK9N"
	vercelBody39 = "2p36q85Q2kBerZWBTjvyXg9p19xjWdGCZTg9ivl"

	vercelLegacy24 = "0a54mfyJ7wM4ois3DtqpBhJn"
	vercelLegacy23 = "OpmpGSKD23nxsGuwmyhNT9R"
)

func TestCircleCIToken(t *testing.T) {
	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantEnd   int
	}{
		{
			name:      "match, min UUID length (20 chars)",
			window:    "CCIPAT_" + circleciUUIDMin20 + "_" + circleciHex40,
			trigStart: 0,
			trigEnd:   7,
			wantOK:    true,
			wantEnd:   7 + 20 + 1 + 40,
		},
		{
			name:      "match, max UUID length (24 chars)",
			window:    "CCIPAT_" + circleciUUIDMax24 + "_" + circleciHex40,
			trigStart: 0,
			trigEnd:   7,
			wantOK:    true,
			wantEnd:   7 + 24 + 1 + 40,
		},
		{
			name:      "match for project token trigger",
			window:    "export CIRCLE_TOKEN=CCIPRJ_" + circleciUUIDMin20 + "_" + circleciHex40,
			trigStart: len("export CIRCLE_TOKEN="),
			trigEnd:   len("export CIRCLE_TOKEN=") + 7,
			wantOK:    true,
			wantEnd:   len("export CIRCLE_TOKEN=") + 7 + 20 + 1 + 40,
		},
		{
			name:      "missing underscore separator rejected",
			window:    "CCIPAT_" + circleciUUIDMin20 + circleciHex40,
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
		{
			name:      "hex segment too short rejected",
			window:    "CCIPAT_" + circleciUUIDMin20 + "_" + circleciHex40[:39],
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
		{
			name:      "hex segment uppercase rejected",
			window:    "CCIPAT_" + circleciUUIDMin20 + "_" + "B402C80B48EBE56E2D187447683752E8BE7CB7C6",
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
		{
			name:      "all-identical UUID rejected",
			window:    "CCIPAT_" + string(makeN('a', 22)) + "_" + circleciHex40,
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window",
			window:    "CCIPAT_",
			trigStart: 0,
			trigEnd:   7,
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := CircleCIToken([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("CircleCIToken(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.trigStart || end != tc.wantEnd) {
				t.Errorf("CircleCIToken(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.trigStart, tc.wantEnd)
			}
		})
	}
}

func TestCircleCITokenNeverPanics(t *testing.T) {
	windows := []string{"", "C", "CCIPAT_", "CCIPAT_" + circleciUUIDMin20[:5], "CCIPAT_" + circleciUUIDMin20 + "_" + circleciHex40, "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("CircleCIToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					CircleCIToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestBuildkiteAPIToken(t *testing.T) {
	const trig = "BUILDKITE_API_TOKEN"

	cases := []struct {
		name      string
		window    string
		trigEnd   int
		wantOK    bool
		wantStart int
		wantEnd   int
	}{
		{
			name:      "equals separator",
			window:    trig + "=" + buildkiteHex40,
			trigEnd:   len(trig),
			wantOK:    true,
			wantStart: len(trig) + 1,
			wantEnd:   len(trig) + 1 + 40,
		},
		{
			name:      "colon separator with spaces",
			window:    trig + " : " + buildkiteHex40,
			trigEnd:   len(trig),
			wantOK:    true,
			wantStart: len(trig + " : "),
			wantEnd:   len(trig+" : ") + 40,
		},
		{
			name:      "double-quoted value",
			window:    trig + `="` + buildkiteHex40 + `"`,
			trigEnd:   len(trig),
			wantOK:    true,
			wantStart: len(trig + `="`),
			wantEnd:   len(trig+`="`) + 40,
		},
		{
			name:    "value too short",
			window:  trig + "=" + buildkiteHex39,
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "uppercase hex rejected",
			window:  trig + "=" + "1C49434FC9FD33BBBC7A692DF5273261B76946C6",
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "missing separator",
			window:  trig + " " + buildkiteHex40,
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "all-identical value rejected",
			window:  trig + "=" + string(makeN('a', 40)),
			trigEnd: len(trig),
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := BuildkiteAPIToken([]byte(tc.window), 0, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("BuildkiteAPIToken(%q, 0, %d) ok = %v, want %v", tc.window, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("BuildkiteAPIToken(%q, 0, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestBuildkiteAPITokenNeverPanics(t *testing.T) {
	windows := []string{"", "B", "BUILDKITE_API_TOKEN", "BUILDKITE_API_TOKEN=", "BUILDKITE_API_TOKEN=\"", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("BuildkiteAPIToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					BuildkiteAPIToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestDatadogAPIKey(t *testing.T) {
	const trig = "DD_API_KEY"

	cases := []struct {
		name    string
		window  string
		trigEnd int
		wantOK  bool
		wantEnd int
	}{
		{
			name:    "match",
			window:  trig + "=" + datadogAPIKey32,
			trigEnd: len(trig),
			wantOK:  true,
			wantEnd: len(trig) + 1 + 32,
		},
		{
			name:    "value too short",
			window:  trig + "=" + datadogAPIKey32[:31],
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "value belonging to the application key length rejected here",
			window:  trig + "=" + datadogAppKey40,
			trigEnd: len(trig),
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := DatadogAPIKey([]byte(tc.window), 0, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("DatadogAPIKey(%q, 0, %d) ok = %v, want %v", tc.window, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != len(trig)+1 || end != tc.wantEnd) {
				t.Errorf("DatadogAPIKey(%q, 0, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigEnd, start, end, len(trig)+1, tc.wantEnd)
			}
		})
	}
}

func TestDatadogAPIKeyNeverPanics(t *testing.T) {
	windows := []string{"", "D", "DD_API_KEY", "DD_API_KEY=", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("DatadogAPIKey(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					DatadogAPIKey([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestDatadogApplicationKey(t *testing.T) {
	const trig = "DD_APP_KEY"

	cases := []struct {
		name    string
		window  string
		trigEnd int
		wantOK  bool
		wantEnd int
	}{
		{
			name:    "match",
			window:  trig + "=" + datadogAppKey40,
			trigEnd: len(trig),
			wantOK:  true,
			wantEnd: len(trig) + 1 + 40,
		},
		{
			name:    "value too short",
			window:  trig + "=" + datadogAppKey40[:39],
			trigEnd: len(trig),
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := DatadogApplicationKey([]byte(tc.window), 0, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("DatadogApplicationKey(%q, 0, %d) ok = %v, want %v", tc.window, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != len(trig)+1 || end != tc.wantEnd) {
				t.Errorf("DatadogApplicationKey(%q, 0, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigEnd, start, end, len(trig)+1, tc.wantEnd)
			}
		})
	}
}

func TestDatadogApplicationKeyNeverPanics(t *testing.T) {
	windows := []string{"", "D", "DD_APP_KEY", "DD_APP_KEY=", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("DatadogApplicationKey(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					DatadogApplicationKey([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestGrafanaServiceAccountToken(t *testing.T) {
	const trig = "glsa_"

	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantEnd   int
	}{
		{
			name:      "match",
			window:    trig + grafanaSABody32 + "_" + grafanaSAChecksum8,
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    true,
			wantEnd:   len(trig) + 32 + 1 + 8,
		},
		{
			name:      "match with surrounding context",
			window:    "Authorization: Bearer " + trig + grafanaSABody32 + "_" + grafanaSAChecksum8,
			trigStart: len("Authorization: Bearer "),
			trigEnd:   len("Authorization: Bearer ") + len(trig),
			wantOK:    true,
			wantEnd:   len("Authorization: Bearer ") + len(trig) + 32 + 1 + 8,
		},
		{
			name:      "checksum uppercase hex accepted",
			window:    trig + grafanaSABody32 + "_" + "E888FFC5",
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    true,
			wantEnd:   len(trig) + 32 + 1 + 8,
		},
		{
			name:      "missing underscore separator rejected",
			window:    trig + grafanaSABody32 + grafanaSAChecksum8,
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    false,
		},
		{
			name:      "checksum too short rejected",
			window:    trig + grafanaSABody32 + "_" + grafanaSAChecksum8[:7],
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    false,
		},
		{
			name:      "placeholder body and checksum rejected",
			window:    trig + string(makeN('X', 32)) + "_" + string(makeN('A', 8)),
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window",
			window:    trig,
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := GrafanaServiceAccountToken([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("GrafanaServiceAccountToken(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.trigStart || end != tc.wantEnd) {
				t.Errorf("GrafanaServiceAccountToken(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.trigStart, tc.wantEnd)
			}
		})
	}
}

func TestGrafanaServiceAccountTokenNeverPanics(t *testing.T) {
	windows := []string{"", "g", "glsa_", "glsa_" + grafanaSABody32[:5], "glsa_" + grafanaSABody32 + "_" + grafanaSAChecksum8, "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("GrafanaServiceAccountToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					GrafanaServiceAccountToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestGrafanaCloudAccessPolicyToken(t *testing.T) {
	const trig = "glc_"

	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantEnd   int
	}{
		{
			name:      "match, min body length (32 chars)",
			window:    trig + grafanaGLCBody32,
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    true,
			wantEnd:   len(trig) + 32,
		},
		{
			name:      "match, max body length (400 chars)",
			window:    trig + grafanaGLCBody400,
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    true,
			wantEnd:   len(trig) + 400,
		},
		{
			name:      "match with padding",
			window:    "GRAFANA_CLOUD_TOKEN=" + trig + grafanaGLCBody32 + "==",
			trigStart: len("GRAFANA_CLOUD_TOKEN="),
			trigEnd:   len("GRAFANA_CLOUD_TOKEN=") + len(trig),
			wantOK:    true,
			wantEnd:   len("GRAFANA_CLOUD_TOKEN=") + len(trig) + 32 + 2,
		},
		{
			name:      "body too short",
			window:    trig + grafanaGLCBody31,
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    false,
		},
		{
			name:      "third padding byte rejected",
			window:    trig + grafanaGLCBody32 + "===",
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    trig + string(makeN('a', 32)),
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := GrafanaCloudAccessPolicyToken([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("GrafanaCloudAccessPolicyToken(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.trigStart || end != tc.wantEnd) {
				t.Errorf("GrafanaCloudAccessPolicyToken(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.trigStart, tc.wantEnd)
			}
		})
	}
}

func TestGrafanaCloudAccessPolicyTokenNeverPanics(t *testing.T) {
	windows := []string{"", "g", "glc_", "glc_" + grafanaGLCBody32[:5], "glc_" + grafanaGLCBody32 + "==", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("GrafanaCloudAccessPolicyToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					GrafanaCloudAccessPolicyToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestDopplerToken(t *testing.T) {
	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantEnd   int
	}{
		{
			name:      "match, no label, min length (40 chars)",
			window:    "dp.pt." + dopplerBody40,
			trigStart: 0,
			trigEnd:   6,
			wantOK:    true,
			wantEnd:   6 + 40,
		},
		{
			name:      "match, no label, max length (44 chars)",
			window:    "dp.ct." + dopplerBody44,
			trigStart: 0,
			trigEnd:   6,
			wantOK:    true,
			wantEnd:   6 + 44,
		},
		{
			name:      "match with environment label",
			window:    "dp.st.dev." + dopplerBody40,
			trigStart: 0,
			trigEnd:   6,
			wantOK:    true,
			wantEnd:   6 + 4 + 40,
		},
		{
			name:      "match for sa/scim/audit triggers",
			window:    "dp.sa." + dopplerBody40,
			trigStart: 0,
			trigEnd:   6,
			wantOK:    true,
			wantEnd:   6 + 40,
		},
		{
			name:      "body too short rejected",
			window:    "dp.pt." + dopplerBody39,
			trigStart: 0,
			trigEnd:   6,
			wantOK:    false,
		},
		{
			name:      "body one char over max rejected",
			window:    "dp.pt." + dopplerBody45,
			trigStart: 0,
			trigEnd:   6,
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    "dp.pt." + string(makeN('a', 42)),
			trigStart: 0,
			trigEnd:   6,
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := DopplerToken([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("DopplerToken(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.trigStart || end != tc.wantEnd) {
				t.Errorf("DopplerToken(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.trigStart, tc.wantEnd)
			}
		})
	}
}

func TestDopplerTokenNeverPanics(t *testing.T) {
	windows := []string{"", "d", "dp.pt.", "dp.st.dev.", "dp.pt." + dopplerBody40[:5], "dp.pt." + dopplerBody40, "dp.st.dev." + dopplerBody40, "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("DopplerToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					DopplerToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestVercelToken(t *testing.T) {
	const trig = "vcp_"

	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantEnd   int
	}{
		{
			name:      "match, min body length (40 chars)",
			window:    trig + vercelBody40,
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    true,
			wantEnd:   len(trig) + 40,
		},
		{
			name:      "match, max body length (80 chars)",
			window:    trig + vercelBody80,
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    true,
			wantEnd:   len(trig) + 80,
		},
		{
			name:      "match for other current triggers",
			window:    "export VERCEL_TOKEN=vck_" + vercelBody40,
			trigStart: len("export VERCEL_TOKEN="),
			trigEnd:   len("export VERCEL_TOKEN=") + 4,
			wantOK:    true,
			wantEnd:   len("export VERCEL_TOKEN=") + 4 + 40,
		},
		{
			name:      "body too short",
			window:    trig + vercelBody39,
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    trig + string(makeN('a', 40)),
			trigStart: 0,
			trigEnd:   len(trig),
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := VercelToken([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("VercelToken(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.trigStart || end != tc.wantEnd) {
				t.Errorf("VercelToken(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.trigStart, tc.wantEnd)
			}
		})
	}
}

func TestVercelTokenNeverPanics(t *testing.T) {
	windows := []string{"", "v", "vcp_", "vcp_" + vercelBody40[:5], "vcp_" + vercelBody80, "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("VercelToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					VercelToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestVercelLegacyToken(t *testing.T) {
	const trig = "VERCEL_TOKEN"

	cases := []struct {
		name    string
		window  string
		trigEnd int
		wantOK  bool
		wantEnd int
	}{
		{
			name:    "match",
			window:  trig + "=" + vercelLegacy24,
			trigEnd: len(trig),
			wantOK:  true,
			wantEnd: len(trig) + 1 + 24,
		},
		{
			name:    "value too short",
			window:  trig + "=" + vercelLegacy23,
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "all-identical value rejected",
			window:  trig + "=" + string(makeN('a', 24)),
			trigEnd: len(trig),
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := VercelLegacyToken([]byte(tc.window), 0, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("VercelLegacyToken(%q, 0, %d) ok = %v, want %v", tc.window, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != len(trig)+1 || end != tc.wantEnd) {
				t.Errorf("VercelLegacyToken(%q, 0, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigEnd, start, end, len(trig)+1, tc.wantEnd)
			}
		})
	}
}

func TestVercelLegacyTokenNeverPanics(t *testing.T) {
	windows := []string{"", "V", "VERCEL_TOKEN", "VERCEL_TOKEN=", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("VercelLegacyToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					VercelLegacyToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}
