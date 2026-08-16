package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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

func TestRunDirSkipsBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	secret := "AKIAUJZDEGXDNCF32EPF"
	binary := append([]byte("key="+secret+"\x00"), make([]byte, 64)...)
	if err := os.WriteFile(filepath.Join(dir, "compiled.bin"), binary, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("ordinary text"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(context.Background(), []string{"dir", dir}, nil, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	var report scanReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 || len(report.Findings) != 0 {
		t.Fatalf("report = %+v, want the binary file skipped and no findings", report)
	}
}

func TestRunDirSkipsUnreadableFiles(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read mode-0 files")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "locked.txt"), []byte("key=AKIAUJZDEGXDNCF32EPF"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("ordinary text"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"dir", dir}, nil, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diagnostics.String(), "skipped 1 unreadable file(s)") {
		t.Fatalf("diagnostics = %q, want unreadable-skip notice", diagnostics.String())
	}
	var report scanReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 || len(report.Findings) != 0 {
		t.Fatalf("report = %+v, want the unreadable file skipped", report)
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

func TestRunDirParallelScanPreservesDeterministicFileOrder(t *testing.T) {
	dir := t.TempDir()
	secret := "AKIAUJZDEGXDNCF32EPF"
	const files = 32
	for i := files - 1; i >= 0; i-- {
		name := filepath.Join(dir, fmt.Sprintf("file-%02d.txt", i))
		// Vary file sizes so workers are unlikely to complete in path order.
		contents := strings.Repeat("ordinary text\n", i*100) + secret
		if err := os.WriteFile(name, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for run := 0; run < 5; run++ {
		var output bytes.Buffer
		if err := runDir(context.Background(), []string{"-profile=fast", "-exit-code=0", dir}, &output, io.Discard); err != nil {
			t.Fatal(err)
		}
		var report scanReport
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.FilesScanned != files || len(report.Findings) != files {
			t.Fatalf("run %d: files=%d findings=%d", run, report.FilesScanned, len(report.Findings))
		}
		for i, finding := range report.Findings {
			want := fmt.Sprintf("file-%02d.txt", i)
			if finding.File != want {
				t.Fatalf("run %d finding %d file = %q, want %q", run, i, finding.File, want)
			}
		}
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

func TestRegularFilesPrunesDefaultDependencyDirectories(t *testing.T) {
	root := t.TempDir()
	excluded := []string{
		"node_modules/pkg/leak.txt",
		"web/bower_components/pkg/leak.txt",
		".git/objects/leak.txt",
		"vendor/github.com/acme/pkg/leak.txt",
		"vendor/golang.org/x/tools/leak.txt",
		"vendor/google.golang.org/grpc/leak.txt",
		"vendor/gopkg.in/yaml.v3/leak.txt",
		"vendor/istio.io/api/leak.txt",
		"vendor/k8s.io/api/leak.txt",
		"vendor/sigs.k8s.io/yaml/leak.txt",
		"vendor/bundle/ruby/leak.txt",
		"vendor/ruby/3.3.0/leak.txt",
		".venv/lib/python3.12/site-packages/leak.txt",
		"virtualenv/lib64/python3.11/site-packages/leak.txt",
		"prefix/lib/python3.12/site-packages/leak.txt",
		"prefix/python/3.12/lib/site-packages/leak.txt",
		"site-packages/example_pkg-1.2.3.dist-info/leak.txt",
		".gitleaks.toml",
		"assets/logo.PNG",
		"assets/font.woff2",
		"documents/report.pdf",
		"bin/dependency.dll",
		"go.mod",
		"go.sum",
		"go.work",
		"go.work.sum",
		"vendor/modules.txt",
		"gradlew",
		"gradlew.bat",
		"gradle.lockfile",
		"mvnw",
		"mvnw.cmd",
		".mvn/wrapper/MavenWrapperDownloader.java",
		"deno.lock",
		"npm-shrinkwrap.json",
		"package-lock.json",
		"pnpm-lock.yaml",
		"yarn.lock",
		"public/jquery-ui.min.js.map",
		"javascript.json",
		"Pipfile.lock",
		"poetry.lock",
		"cache/package.gem",
		"verification-metadata.xml",
		"Database.refactorlog",
	}
	included := []string{
		"src/leak.txt",
		".env",
		"dist/leak.txt",
		"target/leak.txt",
		"vendor/acme.example/pkg/leak.txt",
		"vendor/local/leak.txt",
		"venv/src/leak.txt",
		"package.json",
		"custom.lock",
		"app.js",
		"gitleaks-config.txt",
	}
	for _, name := range append(excluded, included...) {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("not empty"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	paths, _, err := regularFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(paths))
	for i, path := range paths {
		got[i], err = filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		got[i] = filepath.ToSlash(got[i])
	}
	sort.Strings(included)
	if strings.Join(got, "\n") != strings.Join(included, "\n") {
		t.Fatalf("files = %q, want %q", got, included)
	}
}

func TestRegularFilesSkipsEmptyFiles(t *testing.T) {
	root := t.TempDir()
	empty := filepath.Join(root, "empty.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	nonempty := filepath.Join(root, "nonempty.txt")
	if err := os.WriteFile(nonempty, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, _, err := regularFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != nonempty {
		t.Fatalf("files = %q, want only %q", paths, nonempty)
	}
	paths, _, err = regularFiles(empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("explicit empty file was not skipped: %q", paths)
	}
}

func TestRegularFilesScansExplicitFileInsideExcludedDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node_modules", "pkg", "package-lock.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not empty"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, _, err := regularFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != path {
		t.Fatalf("explicit file = %q, want %q", paths, path)
	}
}

func TestRunDirUnreadableSubdirectoryDoesNotAbortScan(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read mode-0 directories")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o700) // allow TempDir cleanup
	secret := "AKIAUJZDEGXDNCF32EPF"
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("key="+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	err := run(context.Background(), []string{"dir", "-profile=fast", "-exit-code=7", dir}, nil, &output, &diagnostics)
	var found findingsError
	if !errors.As(err, &found) || found.code != 7 {
		t.Fatalf("error = %v, want findings exit 7", err)
	}
	if !strings.Contains(diagnostics.String(), "skipped 1 unreadable path(s) while enumerating") {
		t.Fatalf("diagnostics = %q, want unreadable-path notice", diagnostics.String())
	}
	var report scanReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 || len(report.Findings) != 1 {
		t.Fatalf("report = %+v, want the readable file still scanned", report)
	}
}

func TestRunDirScansSymlinkedRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "release-1")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := "AKIAUJZDEGXDNCF32EPF"
	if err := os.WriteFile(filepath.Join(real, "leak.txt"), []byte("key="+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "current")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run(context.Background(), []string{"dir", "-profile=fast", "-exit-code=7", link}, nil, &output, io.Discard)
	var found findingsError
	if !errors.As(err, &found) || found.code != 7 {
		t.Fatalf("error = %v, want findings exit 7", err)
	}
	var report scanReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 || len(report.Findings) != 1 {
		t.Fatalf("report = %+v, want the symlinked root's file scanned", report)
	}
}

func TestRunDirExcludesReportPathThroughSymlinkedRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "release-1")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := "AKIAUJZDEGXDNCF32EPF"
	if err := os.WriteFile(filepath.Join(real, "leak.txt"), []byte("key="+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "current")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(link, "findings.json")
	args := []string{"dir", "-profile=fast", "-exit-code=7", "-report-path=" + reportPath, "-show-secrets", link}

	// First run creates the report inside the symlinked root itself.
	var found findingsError
	if err := run(context.Background(), args, nil, io.Discard, io.Discard); !errors.As(err, &found) {
		t.Fatalf("first run error = %v, want findings exit", err)
	}

	// A second run over the same symlinked root must not treat its own
	// prior report (now sitting under the canonicalized root) as a
	// scannable file: excludePath compares canonicalized paths, so the
	// report path needs the same "current -> release-1" resolution the
	// scan root itself gets, or the report ends up scanning (and, with
	// -show-secrets, re-reporting) its own previous output.
	if err := run(context.Background(), args, nil, io.Discard, io.Discard); !errors.As(err, &found) {
		t.Fatalf("second run error = %v, want findings exit", err)
	}
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report scanReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 {
		t.Fatalf("report.FilesScanned = %d, want 1 (report file must be excluded, not rescanned)", report.FilesScanned)
	}
	for _, f := range report.Findings {
		if f.File != "leak.txt" {
			t.Fatalf("report contains an unexpected finding from %q, report file was not excluded", f.File)
		}
	}
}

func TestRegularFilesSkipsUnreadableSubdirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read mode-0 directories")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o700)
	readable := filepath.Join(root, "readable.txt")
	if err := os.WriteFile(readable, []byte("not empty"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, skipped, err := regularFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	if len(paths) != 1 || paths[0] != readable {
		t.Fatalf("paths = %q, want only %q", paths, readable)
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
