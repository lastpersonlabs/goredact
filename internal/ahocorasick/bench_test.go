package ahocorasick

import (
	"strings"
	"testing"
)

// benchPatterns is a realistic ~40-keyword secret/credential trigger set:
// generic words are case-folded, prefix/format triggers are case-sensitive.
func benchPatterns() []Pattern {
	return []Pattern{
		{Literal: "password", CaseFold: true},
		{Literal: "passwd", CaseFold: true},
		{Literal: "secret", CaseFold: true},
		{Literal: "token", CaseFold: true},
		{Literal: "authorization", CaseFold: true},
		{Literal: "api_key", CaseFold: true},
		{Literal: "apikey", CaseFold: true},
		{Literal: "api-key", CaseFold: true},
		{Literal: "access_key", CaseFold: true},
		{Literal: "secret_key", CaseFold: true},
		{Literal: "private_key", CaseFold: true},
		{Literal: "client_secret", CaseFold: true},
		{Literal: "client_id", CaseFold: true},
		{Literal: "credential", CaseFold: true},
		{Literal: "bearer", CaseFold: true},
		{Literal: "oauth", CaseFold: true},
		{Literal: "session_id", CaseFold: true},
		{Literal: "set-cookie", CaseFold: true},
		{Literal: "x-api-key", CaseFold: true},
		{Literal: "connectionstring", CaseFold: true},
		{Literal: "pwd=", CaseFold: true},
		{Literal: "ssn", CaseFold: true},
		{Literal: "credit card", CaseFold: true},
		{Literal: "iban", CaseFold: true},
		{Literal: "jdbc:", CaseFold: true},
		{Literal: "mongodb://", CaseFold: true},
		{Literal: "postgres://", CaseFold: true},
		{Literal: "AKIA"},
		{Literal: "ASIA"},
		{Literal: "ghp_"},
		{Literal: "gho_"},
		{Literal: "github_pat_"},
		{Literal: "xoxb-"},
		{Literal: "xoxp-"},
		{Literal: "sk_live_"},
		{Literal: "pk_live_"},
		{Literal: "AIza"},
		{Literal: "eyJhbGciOi"},
		{Literal: "-----BEGIN"},
		{Literal: "ssh-rsa "},
		{Literal: "SG."},
	}
}

const loremChunk = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do " +
	"eiusmod tempor incididunt ut dolore magna aliqua. Enim ad minim veniam, " +
	"quis nostrud exercitation ullamco nisi ut aliquip ex ea commodo consequat. " +
	"Duis irure dolor in reprehenderit in voluptate velit esse cillum dolore eu " +
	"fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt " +
	"in culpa qui officia deserunt mollit anim id est. "

// quietInput is 16KiB of lorem-ipsum-ish text with no matches.
func quietInput() []byte {
	var sb strings.Builder
	for sb.Len() < 16*1024 {
		sb.WriteString(loremChunk)
	}
	return []byte(sb.String())[:16*1024]
}

// noisyInput is quietInput salted with many trigger keywords.
func noisyInput() []byte {
	salts := []string{
		"password=hunter2", "SECRET", "Bearer Token", "AKIAIOSFODNN7EXAMPLE",
		"ghp_16charsxxxx", "xoxb-1234", "-----BEGIN RSA PRIVATE_KEY-----",
		"api_key: abc", "Authorization: OAuth", "sk_live_zzz", "eyJhbGciOiJIUzI1",
	}
	quiet := quietInput()
	var sb strings.Builder
	pos, si := 0, 0
	for pos < len(quiet) {
		end := pos + 96
		if end > len(quiet) {
			end = len(quiet)
		}
		sb.Write(quiet[pos:end])
		sb.WriteString(salts[si%len(salts)])
		si++
		pos = end
	}
	return []byte(sb.String())[:16*1024]
}

func benchScan(b *testing.B, input []byte) {
	a, err := Compile(benchPatterns())
	if err != nil {
		b.Fatal(err)
	}
	matches := 0
	fn := func(p, e int) bool {
		matches++
		return true
	}
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Scan(0, input, fn)
	}
	_ = matches
}

func BenchmarkScanQuiet(b *testing.B) {
	input := quietInput()
	if n := len(refMatches(benchPatterns(), input)); n != 0 {
		b.Fatalf("quiet input unexpectedly contains %d matches", n)
	}
	benchScan(b, input)
}

func BenchmarkScanNoisy(b *testing.B) {
	input := noisyInput()
	if n := len(refMatches(benchPatterns(), input)); n == 0 {
		b.Fatal("noisy input contains no matches")
	}
	benchScan(b, input)
}
