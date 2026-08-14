package validators

import (
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"testing"
)

// Synthetic PEM/PPK material for tests. The base64 is random-looking
// invented data, not real key material.
const (
	pemTrig     = "-----BEGIN "
	pemTrigLen  = len(pemTrig)
	pemB64LineA = "rpvGMXOAKGX6B+kpekdCsOtzCoV+ZuCNdBcPTT9hA6rOjKjGc6MefdDU8p5oXcY7"
	pemB64LineB = "rmqoDH0qVi/huXgpY1qHTa43gddwT5TXFrrNosHPdl19o2Z+/7piAa2GqytsZN3C"
	pemB64LineC = "2uCmH6CHd67YEB0uS5MMuWrzaXnJ0gfBwd91bSrUJj9LZRsK1PbRQUyZJjzlxYuw"
)

func rawPEM(label string) string {
	return "-----BEGIN " + label + "-----\n" +
		pemB64LineA + "\n" + pemB64LineB + "\n" + pemB64LineC + "\n" +
		"-----END " + label + "-----\n"
}

// escapedPEM is a JSON-escaped single-line PEM as it appears inside a JSON
// string value in agent logs: literal backslash-n between lines.
func escapedPEM(label string) string {
	return "-----BEGIN " + label + `-----\n` +
		pemB64LineA + `\n` + pemB64LineB + `\n` +
		"-----END " + label + `-----\n`
}

func TestPEMPrivateKey(t *testing.T) {
	openssh := rawPEM("OPENSSH PRIVATE KEY")
	rsa := rawPEM("RSA PRIVATE KEY")
	procType := "-----BEGIN RSA PRIVATE KEY-----\n" +
		"Proc-Type: 4,ENCRYPTED\n" +
		"DEK-Info: AES-128-CBC,A1B2C3D4E5F60718293A4B5C6D7E8F90\n\n" +
		pemB64LineA + "\n" + pemB64LineB + "\n" +
		"-----END RSA PRIVATE KEY-----\n"
	jsonLine := `{"key":"` + escapedPEM("OPENSSH PRIVATE KEY") + `"}`
	truncated := "-----BEGIN PRIVATE KEY-----\n" +
		pemB64LineA + "\n" + pemB64LineB + "\n" + pemB64LineC

	cases := []struct {
		name      string
		window    string
		trigStart int
		wantOK    bool
		wantStart int
		wantEnd   int
	}{
		{
			name:    "raw openssh full block",
			window:  openssh,
			wantOK:  true,
			wantEnd: len(openssh) - 1, // closing dashes included, real trailing newline not consumed
		},
		{
			name:      "raw rsa embedded mid-line",
			window:    "log: " + rsa + " tail",
			trigStart: 5,
			wantOK:    true,
			wantStart: 5,
			wantEnd:   5 + len(rsa) - 1,
		},
		{
			name:    "encrypted pem with Proc-Type and DEK-Info headers",
			window:  procType,
			wantOK:  true,
			wantEnd: len(procType) - 1,
		},
		{
			name:      "json-escaped single-line pem consumes trailing escaped newline",
			window:    jsonLine,
			trigStart: len(`{"key":"`),
			wantOK:    true,
			wantStart: len(`{"key":"`),
			wantEnd:   len(jsonLine) - len(`"}`), // includes the final \n escape, stops before the quote
		},
		{
			name:    "truncated block confirms through last body byte",
			window:  truncated,
			wantOK:  true,
			wantEnd: len(truncated),
		},
		{
			name:    "truncated block with trailing newline excludes the newline",
			window:  truncated + "\n",
			wantOK:  true,
			wantEnd: len(truncated),
		},
		{
			name:    "mismatched END label falls back to truncation span",
			window:  "-----BEGIN RSA PRIVATE KEY-----\n" + pemB64LineA + "\n-----END CERTIFICATE-----",
			wantOK:  true,
			wantEnd: len("-----BEGIN RSA PRIVATE KEY-----\n" + pemB64LineA + "\n-----END CERTIFICATE"), // marker text over-redacted, safe
		},
		{
			name:   "certificate block rejected",
			window: "-----BEGIN CERTIFICATE-----\n" + pemB64LineA + "\n-----END CERTIFICATE-----\n",
			wantOK: false,
		},
		{
			name:   "public key block rejected",
			window: "-----BEGIN PUBLIC KEY-----\n" + pemB64LineA + "\n-----END PUBLIC KEY-----\n",
			wantOK: false,
		},
		{
			name:   "prose mentioning the header rejected",
			window: "-----BEGIN PRIVATE KEY----- is the PEM header",
			wantOK: false,
		},
		{
			name:   "marker-only prose without body rejected",
			window: "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
			wantOK: false,
		},
		{
			name:   "header with unterminated label rejected",
			window: "-----BEGIN PRIVATE KEY",
			wantOK: false,
		},
		{
			name:   "bare header at window end rejected",
			window: "-----BEGIN PRIVATE KEY-----",
			wantOK: false,
		},
		{
			name:   "lowercase label byte rejected",
			window: "-----BEGIN private key-----\n" + pemB64LineA,
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := PEMPrivateKey([]byte(tc.window), tc.trigStart, tc.trigStart+pemTrigLen)
			if ok != tc.wantOK {
				t.Fatalf("PEMPrivateKey ok = %v, want %v (window %q)", ok, tc.wantOK, tc.window)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("PEMPrivateKey span = [%d,%d), want [%d,%d)\nwindow: %q\ngot:    %q",
					start, end, tc.wantStart, tc.wantEnd, tc.window, tc.window[start:end])
			}
		})
	}
}

const ppkTrig = "PuTTY-User-Key-File-"

func rawPPK(version, privLines string) string {
	return "PuTTY-User-Key-File-" + version + ": ssh-rsa\n" +
		"Encryption: none\n" +
		"Comment: synthetic\n" +
		"Public-Lines: 1\n" +
		pemB64LineA + "\n" +
		privLines
}

func TestPuTTYPrivateKey(t *testing.T) {
	full := rawPPK("2", "Private-Lines: 2\n"+pemB64LineB+"\n"+pemB64LineC+"\n"+
		"Private-MAC: 6f1c2b3a4d5e6f708192a3b4c5d6e7f8091a2b3c\n")
	fullSecStart := strings.Index(full, "Private-Lines:")
	fullSecEnd := strings.Index(full, "\nPrivate-MAC:")

	truncated := rawPPK("3", "Private-Lines: 6\n"+pemB64LineB+"\n"+pemB64LineC[:20])

	cases := []struct {
		name      string
		window    string
		trigStart int
		wantOK    bool
		wantStart int
		wantEnd   int
	}{
		{
			name:      "full v2 ppk redacts only the private-lines section",
			window:    full,
			wantOK:    true,
			wantStart: fullSecStart,
			wantEnd:   fullSecEnd,
		},
		{
			name:      "truncated v3 ppk confirms through last body byte",
			window:    truncated,
			wantOK:    true,
			wantStart: strings.Index(truncated, "Private-Lines:"),
			wantEnd:   len(truncated),
		},
		{
			name:      "embedded with prefix",
			window:    ">> " + full,
			trigStart: 3,
			wantOK:    true,
			wantStart: 3 + fullSecStart,
			wantEnd:   3 + fullSecEnd,
		},
		{
			name:   "bad version digit rejected",
			window: rawPPK("9", "Private-Lines: 1\n"+pemB64LineB+"\n"),
			wantOK: false,
		},
		{
			name:   "no private-lines section rejected",
			window: rawPPK("2", "Private-MAC: 6f1c2b3a4d5e6f708192a3b4c5d6e7f8091a2b3c\n"),
			wantOK: false,
		},
		{
			name:   "prose after line count rejected",
			window: "PuTTY-User-Key-File-2: ssh-rsa\nPrivate-Lines: 14 is a field in PPK\n",
			wantOK: false,
		},
		{
			name:   "window cut right after private-lines header rejected (nothing leaked)",
			window: rawPPK("2", "Private-Lines: 6\n"),
			wantOK: false,
		},
		{
			name:   "version digit without colon rejected",
			window: "PuTTY-User-Key-File-2 format\nPrivate-Lines: 1\n" + pemB64LineB + "\n",
			wantOK: false,
		},
		{
			name:   "trigger at window end rejected",
			window: "PuTTY-User-Key-File-",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := PuTTYPrivateKey([]byte(tc.window), tc.trigStart, tc.trigStart+len(ppkTrig))
			if ok != tc.wantOK {
				t.Fatalf("PuTTYPrivateKey ok = %v, want %v (window %q)", ok, tc.wantOK, tc.window)
			}
			if ok && (start != tc.wantStart || end != tc.wantEnd) {
				t.Errorf("PuTTYPrivateKey span = [%d,%d), want [%d,%d)\ngot: %q",
					start, end, tc.wantStart, tc.wantEnd, tc.window[start:end])
			}
		})
	}
}

// TestPrivateKeyTruncationBruteForce feeds every prefix of realistic
// samples to both validators: they must never panic, and any confirmed
// span must be sane and within the window. This mirrors the engine handing
// validators windows truncated at chunk or input boundaries.
func TestPrivateKeyTruncationBruteForce(t *testing.T) {
	pemSamples := []string{
		rawPEM("OPENSSH PRIVATE KEY"),
		rawPEM("RSA PRIVATE KEY"),
		`{"key":"` + escapedPEM("EC PRIVATE KEY") + `"}`,
		"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,A1B2\n\n" + pemB64LineA + "\n-----END RSA PRIVATE KEY-----\n",
		"-----BEGIN CERTIFICATE-----\n" + pemB64LineA + "\n-----END CERTIFICATE-----\n",
	}
	for _, sample := range pemSamples {
		trigStart := strings.Index(sample, pemTrig)
		for cut := 0; cut <= len(sample); cut++ {
			if cut < trigStart+pemTrigLen {
				continue // engine windows always contain the whole trigger
			}
			window := []byte(sample[:cut])
			start, end, ok := PEMPrivateKey(window, trigStart, trigStart+pemTrigLen)
			if !ok {
				continue
			}
			if start != trigStart || end <= start || end > len(window) {
				t.Fatalf("PEMPrivateKey(%q[:%d]) span [%d,%d) out of bounds (trigStart %d)", sample, cut, start, end, trigStart)
			}
		}
	}

	ppkSample := rawPPK("2", "Private-Lines: 2\n"+pemB64LineB+"\n"+pemB64LineC+"\nPrivate-MAC: 6f1c\n")
	for cut := len(ppkTrig); cut <= len(ppkSample); cut++ {
		window := []byte(ppkSample[:cut])
		start, end, ok := PuTTYPrivateKey(window, 0, len(ppkTrig))
		if !ok {
			continue
		}
		if start < 0 || end <= start || end > len(window) {
			t.Fatalf("PuTTYPrivateKey(sample[:%d]) span [%d,%d) out of bounds", cut, start, end)
		}
	}
}

// TestPrivateKeyRandomBytesNeverPanic splices the trigger literals into
// random byte windows: no input may cause a panic or an out-of-window span.
func TestPrivateKeyRandomBytesNeverPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 500; iter++ {
		window := make([]byte, 16+rng.Intn(512))
		rng.Read(window)
		for _, trig := range []string{pemTrig, ppkTrig} {
			if len(trig) > len(window) {
				continue
			}
			at := rng.Intn(len(window) - len(trig) + 1)
			copy(window[at:], trig)
			validate := PEMPrivateKey
			if trig == ppkTrig {
				validate = PuTTYPrivateKey
			}
			start, end, ok := validate(window, at, at+len(trig))
			if ok && (start < 0 || end <= start || end > len(window)) {
				t.Fatalf("iter %d trig %q: span [%d,%d) out of window (len %d)", iter, trig, start, end, len(window))
			}
		}
	}
}

// TestPrivateKeySpecFixtures cross-checks the fixtures declared in
// ../specs/private-keys.json against the validators before the orchestrator
// regenerates the builtin tables, replicating the generated fixture test's
// confirm semantics (any trigger occurrence confirming counts as a match).
func TestPrivateKeySpecFixtures(t *testing.T) {
	data, err := os.ReadFile("../specs/private-keys.json")
	if err != nil {
		t.Fatalf("reading spec: %v", err)
	}
	var spec struct {
		Rules []struct {
			ID       string `json:"id"`
			Triggers []struct {
				Literal string `json:"literal"`
			} `json:"triggers"`
			Validator    string `json:"validator"`
			MaxLookahead int    `json:"maxLookahead"`
			Fixtures     struct {
				Match   []string `json:"match"`
				NoMatch []string `json:"nomatch"`
			} `json:"fixtures"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parsing spec: %v", err)
	}
	validatorsByName := map[string]func([]byte, int, int) (int, int, bool){
		"PEMPrivateKey":   PEMPrivateKey,
		"PuTTYPrivateKey": PuTTYPrivateKey,
	}
	if len(spec.Rules) != 2 {
		t.Fatalf("expected 2 rules in spec, got %d", len(spec.Rules))
	}
	for _, rule := range spec.Rules {
		validate, known := validatorsByName[rule.Validator]
		if !known {
			t.Fatalf("rule %q references unknown validator %q", rule.ID, rule.Validator)
		}
		confirms := func(fixture string) bool {
			b := []byte(fixture)
			for _, trig := range rule.Triggers {
				lit := trig.Literal
				for at := 0; at+len(lit) <= len(b); at++ {
					if string(b[at:at+len(lit)]) != lit {
						continue
					}
					hi := at + len(lit) + rule.MaxLookahead
					if hi > len(b) {
						hi = len(b)
					}
					if _, _, ok := validate(b[:hi], at, at+len(lit)); ok {
						return true
					}
				}
			}
			return false
		}
		for _, fx := range rule.Fixtures.Match {
			if !confirms(fx) {
				t.Errorf("rule %q: match fixture not confirmed: %q", rule.ID, fx)
			}
		}
		for _, fx := range rule.Fixtures.NoMatch {
			if confirms(fx) {
				t.Errorf("rule %q: nomatch fixture confirmed: %q", rule.ID, fx)
			}
		}
	}
}
