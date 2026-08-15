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

// azureSas43Body/azureSas42Body/azureSas44Body/azureSas41Body are
// synthetic standard-base64 runs of exactly 43/42/44/41 characters
// (before the trailing "=" pad), spanning the AzureServiceBusSASKey /
// AzureAppConfigurationSecret body-length boundary [42,44].
const (
	azureSas43Body = "bMnrHontIKARAH+Ggl2JfaQqHu42bojteVs3qfNUfTA"
	azureSas42Body = "FnT0tEuw0dwQ0FIunWe8Cz6SNDCdyZQJiJSZQdoHwH"
	azureSas44Body = "en3SO3oXyGf3azU3iQOpMN0PZLqy1WwMZaMKA3P744B8"
	azureSas41Body = "vkKQlENCzsdfF8j61yX/ZFsan2Cw7gFp6r7O425u8"
)

func TestAzureServiceBusSASKey(t *testing.T) {
	const trig = "SharedAccessKey="

	cases := []struct {
		name      string
		window    string
		trigEnd   int
		wantOK    bool
		wantStart int
		wantEnd   int
	}{
		{
			name:      "match, typical 43-char body",
			window:    trig + azureSas43Body + "=",
			trigEnd:   len(trig),
			wantOK:    true,
			wantStart: len(trig),
			wantEnd:   len(trig) + 43 + 1,
		},
		{
			name:      "match in full connection string",
			window:    "Endpoint=sb://contoso.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;" + trig + azureSas43Body + "=",
			trigEnd:   len("Endpoint=sb://contoso.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;") + len(trig),
			wantOK:    true,
			wantStart: len("Endpoint=sb://contoso.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;") + len(trig),
			wantEnd:   len("Endpoint=sb://contoso.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;") + len(trig) + 43 + 1,
		},
		{
			name:      "match, min body length (42 chars)",
			window:    trig + azureSas42Body + "=",
			trigEnd:   len(trig),
			wantOK:    true,
			wantStart: len(trig),
			wantEnd:   len(trig) + 42 + 1,
		},
		{
			name:      "match, max body length (44 chars)",
			window:    trig + azureSas44Body + "=",
			trigEnd:   len(trig),
			wantOK:    true,
			wantStart: len(trig),
			wantEnd:   len(trig) + 44 + 1,
		},
		{
			name:    "body too short (41 chars)",
			window:  trig + azureSas41Body + "=",
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "missing padding",
			window:  trig + azureSas43Body,
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "double padding rejected (wrong key size)",
			window:  trig + azureSas42Body + "==",
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "all-identical body rejected",
			window:  trig + string(makeN('a', 43)) + "=",
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
			start, end, ok := AzureServiceBusSASKey([]byte(tc.window), 0, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("AzureServiceBusSASKey(%q, 0, %d) ok = %v, want %v", tc.window, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("AzureServiceBusSASKey(%q, 0, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestAzureServiceBusSASKeyNeverPanics(t *testing.T) {
	windows := []string{"", "S", "SharedAccessKey=", "SharedAccessKey=" + azureSas43Body[:10], "SharedAccessKey=" + azureSas43Body + "=", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("AzureServiceBusSASKey(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					AzureServiceBusSASKey([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestAzureAppConfigurationSecret(t *testing.T) {
	const trig = "Secret="

	cases := []struct {
		name      string
		window    string
		trigEnd   int
		wantOK    bool
		wantStart int
		wantEnd   int
	}{
		{
			name:      "match, typical 43-char body",
			window:    trig + azureSas43Body + "=",
			trigEnd:   len(trig),
			wantOK:    true,
			wantStart: len(trig),
			wantEnd:   len(trig) + 43 + 1,
		},
		{
			name:      "match in full connection string",
			window:    "Endpoint=https://contoso.azconfig.io;Id=abcd-e6-s0:tl6ABcdefGHi7kLMno;" + trig + azureSas43Body + "=",
			trigEnd:   len("Endpoint=https://contoso.azconfig.io;Id=abcd-e6-s0:tl6ABcdefGHi7kLMno;") + len(trig),
			wantOK:    true,
			wantStart: len("Endpoint=https://contoso.azconfig.io;Id=abcd-e6-s0:tl6ABcdefGHi7kLMno;") + len(trig),
			wantEnd:   len("Endpoint=https://contoso.azconfig.io;Id=abcd-e6-s0:tl6ABcdefGHi7kLMno;") + len(trig) + 43 + 1,
		},
		{
			name:    "body too short",
			window:  trig + azureSas41Body + "=",
			trigEnd: len(trig),
			wantOK:  false,
		},
		{
			name:    "client_secret prefix does not confuse the trigger match itself, but shape still required",
			window:  "client_secret=notbase64shaped",
			trigEnd: len("client_"),
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := AzureAppConfigurationSecret([]byte(tc.window), 0, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("AzureAppConfigurationSecret(%q, 0, %d) ok = %v, want %v", tc.window, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("AzureAppConfigurationSecret(%q, 0, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestAzureAppConfigurationSecretNeverPanics(t *testing.T) {
	windows := []string{"", "S", "Secret=", "Secret=" + azureSas43Body[:10], "Secret=" + azureSas43Body + "=", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("AzureAppConfigurationSecret(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					AzureAppConfigurationSecret([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

// vaultBody20/vaultBody150 are synthetic [A-Za-z0-9_-] runs of exactly
// 20/150 characters, the VaultServiceToken body-length boundary.
// vaultBatch100 is a synthetic 100-character run, the VaultBatchToken
// minimum.
const (
	vaultBody20   = "odJFCrnl2edlBDdz1C5J"
	vaultBody150  = "au2RJtBRnlWmTSHf6pWkLUyifDLkDmWJ6UuVTAIjvFu7WICPhDeOZIiBOB_Y6sHrFH2ZUCr_lgotu2iXW7GboIRoL3u6aHwnMztVuaP-coUNEhEkk-iqq8vH2BzNZV45pFCiRcDCajhDieQjEJ-Bq8"
	vaultBatch100 = "F80ymm3T207gmhZRnFyy5r2xJ7Fj4mgblEv0-9BZhvWaXH6K2-tyLBhhOhg9uhkxiiEZpFfk1OHAOEHYqM6Ojb6mjBHqSiFVKu4M"
)

func TestVaultServiceToken(t *testing.T) {
	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantEnd   int
	}{
		{
			name:      "match, min body length (20 chars)",
			window:    "hvs." + vaultBody20,
			trigStart: 0,
			trigEnd:   4,
			wantOK:    true,
			wantEnd:   4 + 20,
		},
		{
			name:      "match, max body length (150 chars), with surrounding context",
			window:    "export VAULT_TOKEN=hvs." + vaultBody150,
			trigStart: len("export VAULT_TOKEN="),
			trigEnd:   len("export VAULT_TOKEN=hvs."),
			wantOK:    true,
			wantEnd:   len("export VAULT_TOKEN=hvs.") + 150,
		},
		{
			name:      "body too short",
			window:    "hvs." + vaultBody20[:19],
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "body exceeds max (still matches this alphabet past the boundary)",
			window:    "hvs." + vaultBody150 + "X",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    "hvs." + string(makeN('a', 24)),
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window",
			window:    "hvs.",
			trigStart: 0,
			trigEnd:   4,
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := VaultServiceToken([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("VaultServiceToken(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.trigStart || end != tc.wantEnd) {
				t.Errorf("VaultServiceToken(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.trigStart, tc.wantEnd)
			}
		})
	}
}

func TestVaultServiceTokenNeverPanics(t *testing.T) {
	windows := []string{"", "h", "hvs.", "hvs." + vaultBody20[:5], "hvs." + vaultBody150, "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("VaultServiceToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					VaultServiceToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

func TestVaultBatchToken(t *testing.T) {
	cases := []struct {
		name    string
		window  string
		trigEnd int
		wantOK  bool
		wantEnd int
	}{
		{
			name:    "match, min body length (100 chars)",
			window:  "hvb." + vaultBatch100,
			trigEnd: 4,
			wantOK:  true,
			wantEnd: 4 + 100,
		},
		{
			name:    "body too short",
			window:  "hvb." + vaultBatch100[:99],
			trigEnd: 4,
			wantOK:  false,
		},
		{
			name:    "trigger at very end of window",
			window:  "hvb.",
			trigEnd: 4,
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := VaultBatchToken([]byte(tc.window), 0, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("VaultBatchToken(%q, 0, %d) ok = %v, want %v", tc.window, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != 0 || end != tc.wantEnd) {
				t.Errorf("VaultBatchToken(%q, 0, %d) span = [%d,%d), want [0,%d)", tc.window, tc.trigEnd, start, end, tc.wantEnd)
			}
		})
	}
}

func TestVaultBatchTokenNeverPanics(t *testing.T) {
	windows := []string{"", "h", "hvb.", "hvb." + vaultBatch100[:5], "hvb." + vaultBatch100, "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("VaultBatchToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					VaultBatchToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

// tfPrefix14 is a synthetic 14-character alphanumeric prefix. tfSecret60
// and tfSecret70 are synthetic secrets of exactly 60/70 characters, the
// TerraformCloudAPIToken secret-length boundary; tfSecret59 is one
// character below the minimum.
const (
	tfPrefix14 = "CqWp1OrXXHFOpr"
	tfSecret60 = "4jKEIQOkrtDXtBi10Q71hA1XcW9aTMX1C-CI3-dXRZv7qdYdk2r7xgHWPB6P"
	tfSecret70 = "RWJ1Gk8cgSCifdFzctEq8oB7GVvouNndNWYzjFnMpfS2ViRb1-n3U6t3wI973IPFlJ5F7W"
	tfSecret59 = "Rd_Px-BTHRJJbykE0-E8-5clLCZFNV8S2QT6INGDpyOpxyB9JKmyLDUwMbq"
)

func TestTerraformCloudAPIToken(t *testing.T) {
	const infix = ".atlasv1."

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
			name:      "match, min secret length (60 chars)",
			window:    tfPrefix14 + infix + tfSecret60,
			trigStart: len(tfPrefix14),
			trigEnd:   len(tfPrefix14) + len(infix),
			wantOK:    true,
			wantStart: 0,
			wantEnd:   len(tfPrefix14) + len(infix) + 60,
		},
		{
			name:      "match, max secret length (70 chars)",
			window:    tfPrefix14 + infix + tfSecret70,
			trigStart: len(tfPrefix14),
			trigEnd:   len(tfPrefix14) + len(infix),
			wantOK:    true,
			wantStart: 0,
			wantEnd:   len(tfPrefix14) + len(infix) + 70,
		},
		{
			name:      "match with surrounding context",
			window:    "export TF_TOKEN_app_terraform_io=" + tfPrefix14 + infix + tfSecret60,
			trigStart: len("export TF_TOKEN_app_terraform_io=") + len(tfPrefix14),
			trigEnd:   len("export TF_TOKEN_app_terraform_io=") + len(tfPrefix14) + len(infix),
			wantOK:    true,
			wantStart: len("export TF_TOKEN_app_terraform_io="),
			wantEnd:   len("export TF_TOKEN_app_terraform_io=") + len(tfPrefix14) + len(infix) + 60,
		},
		{
			name:      "secret too short",
			window:    tfPrefix14 + infix + tfSecret59,
			trigStart: len(tfPrefix14),
			trigEnd:   len(tfPrefix14) + len(infix),
			wantOK:    false,
		},
		{
			name:      "prefix shorter than 14 chars (not enough room before trigger)",
			window:    "short" + infix + tfSecret60,
			trigStart: 5,
			trigEnd:   5 + len(infix),
			wantOK:    false,
		},
		{
			name:      "prefix continues past 14 chars (preceding byte still alnum)",
			window:    "X" + tfPrefix14 + infix + tfSecret60,
			trigStart: 1 + len(tfPrefix14),
			trigEnd:   1 + len(tfPrefix14) + len(infix),
			wantOK:    false,
		},
		{
			name:      "all-identical prefix rejected",
			window:    string(makeN('a', 14)) + infix + tfSecret60,
			trigStart: 14,
			trigEnd:   14 + len(infix),
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := TerraformCloudAPIToken([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("TerraformCloudAPIToken(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("TerraformCloudAPIToken(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestTerraformCloudAPITokenNeverPanics(t *testing.T) {
	windows := []string{
		"", ".", ".atlasv1.", tfPrefix14 + ".atlasv1.", tfPrefix14 + ".atlasv1." + tfSecret60,
		"short.atlasv1." + tfSecret60, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("TerraformCloudAPIToken(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					TerraformCloudAPIToken([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

// bedrockLongBody91/bedrockLongBody251 are synthetic standard-base64 runs
// of exactly 91/251 characters, the AWSBedrockLongLivedAPIKey
// body-length boundary; bedrockLongBody90 is one character below the
// minimum.
const (
	bedrockLongBody91  = "JfgLq+nbK894RxgG9oiZ+jgttMkFp1CW54M2NhmABHkuEwjua058LeDKK6jDHz2oCtIsjhvNK4p7MZI/4kf3PGdlDcI"
	bedrockLongBody251 = "fw84Jx3+l8S0QPnuQ0/KZe6lOGPoZa70gyU/4gAIqK4+pdEuNb0lCo7pt/LI198F6sXyriJ1RIaKM+t59SQW6PyEXD0fO8WXt/eqQm4m6bs0tj8HRYkQWO+eiEKDl3mm4vMdfPhLTV3sF0xvwkWE/sD7G6Gb7Kuj4SM2G6MzX9nEWTLLcYJbg/KDTCyGrmfN4eUqlLP1wzqUIvG9LRo7jsCYUlYbHp6VHWVnD8dPCi7M0orfeM/omErX6V1"
	bedrockLongBody90  = "t1m+0JeVB44EUmVThYJyp6lBcgQFqAiABDQsaJsqGwodqbTEPcwHgq1oi85Un5CfM6dh9Z2n+4jkPsiqJPWL63moB3"
	// bedrockLongBody91Alt is a second, distinct 91-char body used
	// alongside padding characters: min/max bound only the non-padding
	// base64 run (matching the upstream gitleaks regex this shape is
	// modeled on, {min,max}={0,2}), so a padding test needs a body
	// already at/above the minimum, not a shorter one "topped up" by
	// padding.
	bedrockLongBody91Alt = "eKs7Vm6/c3V3YwhnpWtmu/qXIxWighxhvLJjnhm6QQ4vqkOgIVxjoM/U3f81kTqltNn24esanpqcRp/H6RXlelAZyZH"
)

func TestAWSBedrockLongLivedAPIKey(t *testing.T) {
	const anchor = "ABSKQmVkcm9ja0FQSUtleS"

	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantEnd   int
	}{
		{
			name:      "match, min body length (91 chars)",
			window:    anchor + bedrockLongBody91,
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    true,
			wantEnd:   len(anchor) + 91,
		},
		{
			name:      "match, max body length (251 chars)",
			window:    anchor + bedrockLongBody251,
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    true,
			wantEnd:   len(anchor) + 251,
		},
		{
			name:      "match with one '=' padding byte",
			window:    anchor + bedrockLongBody91Alt + "=",
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    true,
			wantEnd:   len(anchor) + 91 + 1,
		},
		{
			name:      "match with two '=' padding bytes, with surrounding context",
			window:    "AWS_BEARER_TOKEN_BEDROCK=" + anchor + bedrockLongBody91Alt + "==",
			trigStart: len("AWS_BEARER_TOKEN_BEDROCK="),
			trigEnd:   len("AWS_BEARER_TOKEN_BEDROCK=") + len(anchor),
			wantOK:    true,
			wantEnd:   len("AWS_BEARER_TOKEN_BEDROCK=") + len(anchor) + 91 + 2,
		},
		{
			name:      "body too short",
			window:    anchor + bedrockLongBody90,
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    false,
		},
		{
			name:      "third padding byte rejected",
			window:    anchor + bedrockLongBody91Alt + "===",
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    anchor + string(makeN('a', 91)),
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window",
			window:    anchor,
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := AWSBedrockLongLivedAPIKey([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("AWSBedrockLongLivedAPIKey(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.trigStart || end != tc.wantEnd) {
				t.Errorf("AWSBedrockLongLivedAPIKey(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.trigStart, tc.wantEnd)
			}
		})
	}
}

func TestAWSBedrockLongLivedAPIKeyNeverPanics(t *testing.T) {
	const anchor = "ABSKQmVkcm9ja0FQSUtleS"
	windows := []string{"", "A", anchor, anchor + bedrockLongBody91[:10], anchor + bedrockLongBody251, "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("AWSBedrockLongLivedAPIKey(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					AWSBedrockLongLivedAPIKey([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}

// bedrockShortBody20/bedrockShortBody19 are synthetic standard-base64
// runs of exactly 20/19 characters, spanning the
// AWSBedrockShortLivedAPIKey minimum body length.
const (
	bedrockShortBody20 = "5D0R6Z1mO2OGVt8ilkl3"
	bedrockShortBody19 = "mVqhQp0T2gKNTnBt9Cn"
)

func TestAWSBedrockShortLivedAPIKey(t *testing.T) {
	const anchor = "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t"

	cases := []struct {
		name      string
		window    string
		trigStart int
		trigEnd   int
		wantOK    bool
		wantEnd   int
	}{
		{
			name:      "match, min body length (20 chars)",
			window:    anchor + bedrockShortBody20,
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    true,
			wantEnd:   len(anchor) + 20,
		},
		{
			name:      "match, long body (STS-session-token-shaped)",
			window:    anchor + strings.Repeat(bedrockShortBody20, 20),
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    true,
			wantEnd:   len(anchor) + 20*20,
		},
		{
			name:      "match with padding, with surrounding context",
			window:    "Authorization: Bearer " + anchor + bedrockShortBody20 + "==",
			trigStart: len("Authorization: Bearer "),
			trigEnd:   len("Authorization: Bearer ") + len(anchor),
			wantOK:    true,
			wantEnd:   len("Authorization: Bearer ") + len(anchor) + 20 + 2,
		},
		{
			name:      "body too short",
			window:    anchor + bedrockShortBody19,
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    false,
		},
		{
			name:      "all-identical body rejected",
			window:    anchor + string(makeN('a', 20)),
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    false,
		},
		{
			name:      "trigger at very end of window",
			window:    anchor,
			trigStart: 0,
			trigEnd:   len(anchor),
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := AWSBedrockShortLivedAPIKey([]byte(tc.window), tc.trigStart, tc.trigEnd)
			if ok != tc.wantOK {
				t.Fatalf("AWSBedrockShortLivedAPIKey(%q, %d, %d) ok = %v, want %v", tc.window, tc.trigStart, tc.trigEnd, ok, tc.wantOK)
			}
			if ok && (start != tc.trigStart || end != tc.wantEnd) {
				t.Errorf("AWSBedrockShortLivedAPIKey(%q, %d, %d) span = [%d,%d), want [%d,%d)", tc.window, tc.trigStart, tc.trigEnd, start, end, tc.trigStart, tc.wantEnd)
			}
		})
	}
}

func TestAWSBedrockShortLivedAPIKeyNeverPanics(t *testing.T) {
	const anchor = "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t"
	windows := []string{"", "b", anchor, anchor + bedrockShortBody20[:5], anchor + bedrockShortBody20 + "==", "\x00\x00\x00\x00\x00"}
	for _, w := range windows {
		for trigStart := 0; trigStart <= len(w); trigStart++ {
			for trigEnd := trigStart; trigEnd <= len(w); trigEnd++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("AWSBedrockShortLivedAPIKey(%q, %d, %d) panicked: %v", w, trigStart, trigEnd, r)
						}
					}()
					AWSBedrockShortLivedAPIKey([]byte(w), trigStart, trigEnd)
				}()
			}
		}
	}
}
