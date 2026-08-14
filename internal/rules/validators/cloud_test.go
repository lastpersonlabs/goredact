package validators

import (
	"strings"
	"testing"
)

// body16 is a 16-character RFC-4648 upper-base32 body: "AKIA" + body16 is a
// well-formed synthetic AWS access key ID.
const body16 = "UJZDEGXDNCF32EPF"

// secret40 is a 40-character value from the AWS secret access key
// alphabet, not all-identical and not the AWS docs placeholder.
const secret40 = "fKm/r5kJP1VrT+1FJors/6ILi8IHn5kxsC7tVO/H"

// gcpBody35 is a 35-character body from the GCP API key alphabet.
const gcpBody35 = "zyN9zHYIa4UOrGNATMuDJawTgsu8PO_799n"

// azureBody86 is an 86-character run from the Azure storage account key
// (unpadded base64) alphabet; azureBody86+"==" is a well-formed synthetic
// 64-byte key.
const azureBody86 = "5suKcNd8Zra9A9sKPxZ9W3qLy7zKUVQDT7S8sTQCBNR3YbDgbleph1QHt61QTC4XATWS8PHp9NHfYjFM5DI4pZ"

func TestAWSAccessKeyID(t *testing.T) {
	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantStart int
		wantEnd   int
	}{
		{
			name:      "match at window start",
			window:    "AKIA" + body16,
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   4 + 16,
		},
		{
			name:      "match with trailing context",
			window:    "key=AKIA" + body16 + ";",
			trigStart: 4,
			trigEnd:   8,
			wantOK:    true,
			wantStart: 4,
			wantEnd:   8 + 16,
		},
		{
			name:      "match for ASIA trigger",
			window:    "ASIA" + body16,
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   4 + 16,
		},
		{
			name:      "match for ABIA trigger",
			window:    "ABIA" + body16,
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   4 + 16,
		},
		{
			name:      "match for ACCA trigger",
			window:    "ACCA" + body16,
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   4 + 16,
		},
		{
			name:      "window truncated shorter than token",
			window:    "AKIA" + body16[:10],
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window, zero bytes follow",
			window:    "AKIA",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "preceding uppercase letter rejected",
			window:    "XAKIA" + body16,
			trigStart: 1,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "preceding digit rejected",
			window:    "9AKIA" + body16,
			trigStart: 1,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "preceding lowercase letter accepted (narrower boundary alphabet)",
			window:    "xAKIA" + body16,
			trigStart: 1,
			trigEnd:   5,
			wantOK:    true,
			wantStart: 1,
			wantEnd:   5 + 16,
		},
		{
			name:      "trailing digit rejected",
			window:    "AKIA" + body16 + "9",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "trailing uppercase letter rejected",
			window:    "AKIA" + body16 + "Z",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "trailing non-alnum accepted",
			window:    "AKIA" + body16 + ".",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   4 + 16,
		},
		{
			name:      "lowercase body rejected (wrong alphabet)",
			window:    "AKIA" + strings.ToLower(body16),
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "body containing invalid base32 digit rejected",
			window:    "AKIA" + "0JZDEGXDNCF32EPF",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "AWS docs canonical placeholder rejected",
			window:    "AKIAIOSFODNN7EXAMPLE",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "any body ending in EXAMPLE rejected",
			window:    "AKIA" + "ABCDEFGHIEXAMPLE",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := AWSAccessKeyID([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("AWSAccessKeyID(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("AWSAccessKeyID(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestAWSAccessKeyIDNeverPanics(t *testing.T) {
	windows := []string{"", "A", "AKIA", "AKIA" + body16[:5], "\x00\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("AWSAccessKeyID(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					AWSAccessKeyID([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestAWSSecretAccessKey(t *testing.T) {
	cases := []struct {
		name      string
		window    string
		trigEnd   int
		wantOK    bool
		wantStart int
		wantEnd   int
	}{
		{
			name:      "equals separator, no spaces",
			window:    "aws_secret_access_key=" + secret40,
			trigEnd:   len("aws_secret_access_key"),
			wantOK:    true,
			wantStart: len("aws_secret_access_key=") + 0,
			wantEnd:   len("aws_secret_access_key=") + 40,
		},
		{
			name:      "colon separator with surrounding spaces",
			window:    "aws_secret_access_key : " + secret40,
			trigEnd:   len("aws_secret_access_key"),
			wantOK:    true,
			wantStart: len("aws_secret_access_key : "),
			wantEnd:   len("aws_secret_access_key : ") + 40,
		},
		{
			name:      "double-quoted value",
			window:    `aws_secret_access_key="` + secret40 + `"`,
			trigEnd:   len("aws_secret_access_key"),
			wantOK:    true,
			wantStart: len(`aws_secret_access_key="`),
			wantEnd:   len(`aws_secret_access_key="`) + 40,
		},
		{
			name:      "single-quoted value",
			window:    "aws_secret_access_key = '" + secret40 + "'",
			trigEnd:   len("aws_secret_access_key"),
			wantOK:    true,
			wantStart: len("aws_secret_access_key = '"),
			wantEnd:   len("aws_secret_access_key = '") + 40,
		},
		{
			name:    "value too short (truncated window)",
			window:  "aws_secret_access_key=tooshort",
			trigEnd: len("aws_secret_access_key"),
			wantOK:  false,
		},
		{
			name:    "trigger at very end of window",
			window:  "aws_secret_access_key",
			trigEnd: len("aws_secret_access_key"),
			wantOK:  false,
		},
		{
			name:    "missing separator",
			window:  "aws_secret_access_key " + secret40,
			trigEnd: len("aws_secret_access_key"),
			wantOK:  false,
		},
		{
			name:    "value contains disallowed character",
			window:  "aws_secret_access_key=" + secret40[:39] + "!",
			trigEnd: len("aws_secret_access_key"),
			wantOK:  false,
		},
		{
			name:    "all-identical value rejected",
			window:  "aws_secret_access_key=" + string(makeN('a', 40)),
			trigEnd: len("aws_secret_access_key"),
			wantOK:  false,
		},
		{
			name:    "AWS docs placeholder secret rejected",
			window:  "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			trigEnd: len("aws_secret_access_key"),
			wantOK:  false,
		},
		{
			name:    "unmatched closing quote rejected",
			window:  `aws_secret_access_key="` + secret40,
			trigEnd: len("aws_secret_access_key"),
			wantOK:  false,
		},
		{
			name:    "value run longer than 40 chars rejected",
			window:  "aws_secret_access_key=" + secret40 + "X",
			trigEnd: len("aws_secret_access_key"),
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// trigStart is irrelevant to this validator's logic (only
			// trigEnd is consulted), so pass 0 throughout.
			start, end, ok := AWSSecretAccessKey([]byte(tc.window), 0, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("AWSSecretAccessKey(%q, 0, %d) ok = %v, want %v", tc.window, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("AWSSecretAccessKey(%q, 0, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestAWSSecretAccessKeyNeverPanics(t *testing.T) {
	windows := []string{"", "a", "aws_secret_access_key", "aws_secret_access_key=", "aws_secret_access_key=\"", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("AWSSecretAccessKey(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					AWSSecretAccessKey([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestGCPAPIKey(t *testing.T) {
	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantStart int
		wantEnd   int
	}{
		{
			name:      "match at window start",
			window:    "AIza" + gcpBody35,
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   4 + 35,
		},
		{
			name:      "match with trailing context",
			window:    "key=AIza" + gcpBody35 + "&x=1",
			trigStart: 4,
			trigEnd:   8,
			wantOK:    true,
			wantStart: 4,
			wantEnd:   8 + 35,
		},
		{
			name:      "window truncated shorter than token",
			window:    "AIza" + gcpBody35[:10],
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window",
			window:    "AIza",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "preceding alnum char rejected",
			window:    "xAIza" + gcpBody35,
			trigStart: 1,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "preceding underscore rejected",
			window:    "_AIza" + gcpBody35,
			trigStart: 1,
			trigEnd:   5,
			wantOK:    false,
		},
		{
			name:      "trailing hyphen rejected (extends body)",
			window:    "AIza" + gcpBody35 + "-",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "trailing non-alphabet char accepted",
			window:    "AIza" + gcpBody35 + " ",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantStart: 0,
			wantEnd:   4 + 35,
		},
		{
			name:      "body containing invalid char rejected",
			window:    "AIza" + "!" + gcpBody35[1:],
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    "AIza" + string(makeN('x', 35)),
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := GCPAPIKey([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("GCPAPIKey(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("GCPAPIKey(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestGCPAPIKeyNeverPanics(t *testing.T) {
	windows := []string{"", "A", "AIza", "AIza" + gcpBody35[:5], "\x00\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("GCPAPIKey(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					GCPAPIKey([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestAzureStorageAccountKey(t *testing.T) {
	const trig = "AccountKey="

	cases := []struct {
		name      string
		window    string
		trigEnd   int
		wantOK    bool
		wantStart int
		wantEnd   int
	}{
		{
			name:      "match, 86-char body, bare",
			window:    trig + azureBody86 + "==",
			trigEnd:   len(trig),
			wantOK:    true,
			wantStart: len(trig),
			wantEnd:   len(trig) + 86 + 2,
		},
		{
			name:      "match in connection string with trailing semicolon",
			window:    "DefaultEndpointsProtocol=https;" + trig + azureBody86 + "==;EndpointSuffix=core.windows.net",
			trigEnd:   len("DefaultEndpointsProtocol=https;") + len(trig),
			wantOK:    true,
			wantStart: len("DefaultEndpointsProtocol=https;") + len(trig),
			wantEnd:   len("DefaultEndpointsProtocol=https;") + len(trig) + 86 + 2,
		},
		{
			name:      "match, 88-char body (upper bound of range)",
			window:    trig + azureBody86 + "AB" + "==",
			trigEnd:   len(trig),
			wantOK:    true,
			wantStart: len(trig),
			wantEnd:   len(trig) + 88 + 2,
		},
		{
			name:    "body too short",
			window:  trig + azureBody86[:40] + "==",
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "body too long (89 chars before padding)",
			window:  trig + azureBody86 + "ABC" + "==",
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "truncated window: base64 run hits end without ==",
			window:  trig + azureBody86,
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "truncated window: only one = present at end",
			window:  trig + azureBody86 + "=",
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "wrong padding characters",
			window:  trig + azureBody86 + "!!",
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "extra trailing = padding rejected",
			window:  trig + azureBody86 + "===",
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "trigger at very end of window",
			window:  trig,
			trigEnd: len(trig),
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// trigStart is irrelevant to this validator's logic (only
			// trigEnd is consulted), so pass 0 throughout.
			start, end, ok := AzureStorageAccountKey([]byte(tc.window), 0, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("AzureStorageAccountKey(%q, 0, %d) ok = %v, want %v", tc.window, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("AzureStorageAccountKey(%q, 0, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestAzureStorageAccountKeyNeverPanics(t *testing.T) {
	windows := []string{"", "A", "AccountKey=", "AccountKey=" + azureBody86[:20], "AccountKey=" + azureBody86 + "=", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("AzureStorageAccountKey(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					AzureStorageAccountKey([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}
