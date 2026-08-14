package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/lastpersonlabs/goredact"
)

type dirOptions struct {
	profile      string
	reportFormat string
	reportPath   string
	exitCode     int
	showSecrets  bool
}

type reportFinding struct {
	RuleID     string `json:"rule_id"`
	Confidence string `json:"confidence"`
	File       string `json:"file"`
	StartByte  int64  `json:"start_byte"`
	EndByte    int64  `json:"end_byte"`
	Secret     string `json:"secret,omitempty"`
}

type scanReport struct {
	Schema       string          `json:"schema"`
	Profile      string          `json:"profile"`
	FilesScanned int             `json:"files_scanned"`
	BytesRead    int64           `json:"bytes_read"`
	Findings     []reportFinding `json:"findings"`
	ShowsSecrets bool            `json:"shows_secrets"`
}

type findingsError struct{ code int }

func (e findingsError) Error() string { return "goredact: findings detected" }

type fileScanResult struct {
	index     int
	bytesRead int64
	findings  []reportFinding
	err       error
	canceled  bool
}

func runDir(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("goredact dir", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o dirOptions
	fs.StringVar(&o.profile, "profile", "balanced", "detection profile: fast, balanced, or deep")
	fs.StringVar(&o.reportFormat, "report-format", "json", "report format: json, csv, junit, or sarif")
	fs.StringVar(&o.reportPath, "report-path", "-", "report file ('-' for stdout)")
	fs.IntVar(&o.exitCode, "exit-code", 1, "exit code when findings are present (0 disables)")
	fs.BoolVar(&o.showSecrets, "show-secrets", false, "include matched secret values in the report (unsafe)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("goredact dir: exactly one path is required")
	}
	if o.exitCode < 0 || o.exitCode > 125 {
		return errors.New("goredact dir: -exit-code must be between 0 and 125")
	}
	format := strings.ToLower(o.reportFormat)
	if !validReportFormat(format) {
		return errors.New("goredact dir: unknown report format (use json, csv, junit, or sarif)")
	}
	profile, err := parseProfile(o.profile)
	if err != nil {
		return err
	}

	root, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return errors.New("goredact dir: cannot resolve scan path")
	}
	paths, err := regularFiles(root)
	if err != nil {
		return errors.New("goredact dir: cannot enumerate scan path")
	}
	if o.reportPath != "-" {
		reportPath, resolveErr := filepath.Abs(o.reportPath)
		if resolveErr != nil {
			return errors.New("goredact dir: cannot resolve report path")
		}
		paths = excludePath(paths, reportPath)
	}
	report := scanReport{Schema: "goredact/v1", Profile: profile.String(), Findings: []reportFinding{}, ShowsSecrets: o.showSecrets}
	results, err := scanFiles(ctx, root, paths, profile, o.showSecrets)
	if err != nil {
		return err
	}
	for _, result := range results {
		report.FilesScanned++
		report.BytesRead += result.bytesRead
		report.Findings = append(report.Findings, result.findings...)
	}

	if err := writeReport(o.reportPath, format, report, stdout); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "goredact: secrets_found=%d\n", len(report.Findings))
	if len(report.Findings) > 0 && o.exitCode != 0 {
		return findingsError{code: o.exitCode}
	}
	return nil
}

func scanFiles(ctx context.Context, root string, paths []string, profile goredact.Profile, showSecrets bool) ([]fileScanResult, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	workerCount := min(len(paths), runtime.GOMAXPROCS(0))
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	completed := make(chan fileScanResult, len(paths))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			var findings []reportFinding
			var rel string
			engine, err := goredact.New(goredact.Config{Profile: profile, OnFinding: func(f goredact.Finding) {
				findings = append(findings, reportFinding{
					RuleID: f.RuleID, Confidence: f.Confidence.String(), File: rel,
					StartByte: f.Start, EndByte: f.End,
				})
			}})
			if err != nil {
				completed <- fileScanResult{err: fmt.Errorf("goredact dir: configure engine: %w", err)}
				cancel()
				return
			}
			for index := range jobs {
				rel = relativeScanPath(root, paths[index])
				findings = make([]reportFinding, 0)
				result := scanFile(scanCtx, engine, paths[index], index, &findings, showSecrets)
				result.findings = findings
				completed <- result
				if result.err != nil {
					cancel()
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range paths {
			select {
			case jobs <- index:
			case <-scanCtx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(completed)
	}()

	results := make([]fileScanResult, len(paths))
	completedCount := 0
	var firstErr error
	var canceledErr error
	for result := range completed {
		if result.err != nil {
			if result.canceled && canceledErr == nil {
				canceledErr = result.err
			} else if !result.canceled && firstErr == nil {
				firstErr = result.err
			}
			continue
		}
		results[result.index] = result
		completedCount++
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if canceledErr != nil {
		return nil, canceledErr
	}
	if completedCount != len(paths) {
		return nil, safeScanError(scanCtx.Err())
	}
	return results, nil
}

func relativeScanPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		rel = filepath.Base(path)
	}
	return filepath.ToSlash(rel)
}

func scanFile(ctx context.Context, engine *goredact.Engine, path string, index int, findings *[]reportFinding, showSecrets bool) fileScanResult {
	result := fileScanResult{index: index}
	file, err := os.Open(path)
	if err != nil {
		result.err = errors.New("goredact dir: cannot open input file")
		return result
	}
	stats, err := engine.Redact(ctx, io.Discard, file)
	if err != nil {
		_ = file.Close()
		result.canceled = errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		result.err = safeScanError(err)
		return result
	}
	result.bytesRead = stats.BytesRead
	if showSecrets {
		if err := loadSecrets(file, *findings); err != nil {
			_ = file.Close()
			result.err = errors.New("goredact dir: cannot read matched secret")
			return result
		}
	}
	if err := file.Close(); err != nil {
		result.err = errors.New("goredact dir: cannot close input file")
	}
	return result
}

func loadSecrets(file *os.File, findings []reportFinding) error {
	maxInt := int64(^uint(0) >> 1)
	for i := range findings {
		length := findings[i].EndByte - findings[i].StartByte
		if length < 0 || length > maxInt {
			return errors.New("invalid finding range")
		}
		secret := make([]byte, int(length))
		if _, err := io.ReadFull(io.NewSectionReader(file, findings[i].StartByte, length), secret); err != nil {
			return err
		}
		findings[i].Secret = string(secret)
	}
	return nil
}

func excludePath(paths []string, excluded string) []string {
	kept := paths[:0]
	for _, path := range paths {
		if path != excluded {
			kept = append(kept, path)
		}
	}
	return kept
}

func regularFiles(root string) ([]string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if info.Mode().IsRegular() {
		if info.Size() == 0 {
			return nil, nil
		}
		return []string{root}, nil
	}
	if !info.IsDir() {
		return nil, errors.New("not a regular file or directory")
	}
	var paths []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() && rel != "." && defaultExcludedDirectory(rel) {
			return filepath.SkipDir
		}
		if entry.Type().IsRegular() {
			if defaultExcludedFile(rel) {
				return nil
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				return infoErr
			}
			if info.Size() == 0 {
				return nil
			}
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

// These are Gitleaks' default dependency and repository metadata exclusions.
// Keep them narrow: directories such as dist, target, and vendor in general may
// contain first-party source or credentials and are intentionally scanned.
var defaultExcludedDirectoryPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:^|/)node_modules(?:/.*)?$`),
	regexp.MustCompile(`(?:^|/)bower_components(?:/.*)?$`),
	regexp.MustCompile(`(?:^|/)\.git$`),
	regexp.MustCompile(`(?:^|/)vendor/(?:github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)(?:/.*)?$`),
	regexp.MustCompile(`(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$`),
	regexp.MustCompile(`(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$`),
	regexp.MustCompile(`(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\.\d{1,2})+|python/[23](?:\.\d{1,2})+/lib(?:64)?)(?:/.*)?$`),
	regexp.MustCompile(`(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:/.+)?$`),
}

func defaultExcludedDirectory(path string) bool {
	for _, pattern := range defaultExcludedDirectoryPatterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

var defaultExcludedFilePatterns = []*regexp.Regexp{
	regexp.MustCompile(`gitleaks\.toml`),
	regexp.MustCompile(`(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$`),
	regexp.MustCompile(`(?i)\.(?:eot|[ot]tf|woff2?)$`),
	regexp.MustCompile(`(?i)\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$`),
	regexp.MustCompile(`go\.(?:mod|sum|work(?:\.sum)?)$`),
	regexp.MustCompile(`(?:^|/)vendor/modules\.txt$`),
	regexp.MustCompile(`(?:^|/)gradlew(?:\.bat)?$`),
	regexp.MustCompile(`(?:^|/)gradle\.lockfile$`),
	regexp.MustCompile(`(?:^|/)mvnw(?:\.cmd)?$`),
	regexp.MustCompile(`(?:^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$`),
	regexp.MustCompile(`(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$`),
	regexp.MustCompile(`(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$`),
	regexp.MustCompile(`(?:^|/)javascript\.json$`),
	regexp.MustCompile(`(?:^|/)(?:Pipfile|poetry)\.lock$`),
	regexp.MustCompile(`\.gem$`),
	regexp.MustCompile(`verification-metadata\.xml`),
	regexp.MustCompile(`Database.refactorlog`),
}

func defaultExcludedFile(path string) bool {
	for _, pattern := range defaultExcludedFilePatterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}
