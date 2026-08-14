package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDirJSONReport(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := "AKIAUJZDEGXDNCF32EPF"
	if err := os.WriteFile(filepath.Join(dir, "nested", "leak.txt"), []byte("key="+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("ordinary text"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	err := run(context.Background(), []string{"dir", "-profile=fast", "-exit-code=7", dir}, nil, &output, &diagnostics)
	var found findingsError
	if !errors.As(err, &found) || found.code != 7 {
		t.Fatalf("error = %v, want findings exit 7", err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("report contains secret material")
	}
	if diagnostics.String() != "goredact: secrets_found=1\n" {
		t.Fatalf("diagnostics = %q", diagnostics.String())
	}
	var report scanReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 2 || len(report.Findings) != 1 {
		t.Fatalf("report = %+v", report)
	}
	finding := report.Findings[0]
	if finding.File != "nested/leak.txt" || finding.RuleID != "aws-access-key-id" || finding.EndByte <= finding.StartByte {
		t.Fatalf("finding = %+v", finding)
	}
}

func TestRunDirReportsZeroSecretsToStderr(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("ordinary text"), 0o600); err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"dir", dir}, nil, io.Discard, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if diagnostics.String() != "goredact: secrets_found=0\n" {
		t.Fatalf("diagnostics = %q", diagnostics.String())
	}
}

func TestRunDirReportFormats(t *testing.T) {
	dir := t.TempDir()
	secret := "AKIAUJZDEGXDNCF32EPF"
	if err := os.WriteFile(filepath.Join(dir, "leak.txt"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"csv", "junit", "sarif"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(context.Background(), []string{"dir", "-profile=fast", "-exit-code=0", "-show-secrets", "-report-format=" + format, dir}, nil, &output, io.Discard); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), secret) {
				t.Fatalf("%s report omitted secret with -show-secrets", format)
			}
			switch format {
			case "csv":
				records, err := csv.NewReader(&output).ReadAll()
				if err != nil || len(records) != 2 {
					t.Fatalf("CSV records = %v, %v", records, err)
				}
			case "junit":
				var suite junitSuite
				if err := xml.Unmarshal(output.Bytes(), &suite); err != nil || suite.Failures != 1 {
					t.Fatalf("JUnit = %+v, %v", suite, err)
				}
			case "sarif":
				var report sarifReport
				if err := json.Unmarshal(output.Bytes(), &report); err != nil || len(report.Runs) != 1 || len(report.Runs[0].Results) != 1 {
					t.Fatalf("SARIF = %+v, %v", report, err)
				}
			}
		})
	}
}

func TestRunDirJSONShowSecretsIsExplicit(t *testing.T) {
	dir := t.TempDir()
	secret := "AKIAUJZDEGXDNCF32EPF"
	if err := os.WriteFile(filepath.Join(dir, "leak.txt"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(context.Background(), []string{"dir", "-profile=fast", "-exit-code=0", "-show-secrets", dir}, nil, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	var report scanReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.ShowsSecrets || len(report.Findings) != 1 || report.Findings[0].Secret != secret {
		t.Fatalf("report = %+v", report)
	}
}

func TestRunDirExcludesExistingReport(t *testing.T) {
	dir := t.TempDir()
	secret := "AKIAUJZDEGXDNCF32EPF"
	if err := os.WriteFile(filepath.Join(dir, "input.txt"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(reportPath, []byte(secret+"\n"+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"dir", "-profile=fast", "-exit-code=0", "-report-path=" + reportPath, dir}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report scanReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 || len(report.Findings) != 1 {
		t.Fatalf("report rescanned itself: %+v", report)
	}
}

func TestRunRequiresCommand(t *testing.T) {
	if err := run(context.Background(), nil, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("missing command succeeded")
	}
	if err := run(context.Background(), []string{"-profile=fast"}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("legacy top-level flags succeeded")
	}
}
