package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return safeScanError(err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			rel = filepath.Base(path)
		}
		rel = filepath.ToSlash(rel)
		fileFindings := make([]reportFinding, 0)
		engine, err := goredact.New(goredact.Config{Profile: profile, OnFinding: func(f goredact.Finding) {
			fileFindings = append(fileFindings, reportFinding{
				RuleID: f.RuleID, Confidence: f.Confidence.String(), File: rel,
				StartByte: f.Start, EndByte: f.End,
			})
		}})
		if err != nil {
			return fmt.Errorf("goredact dir: configure engine: %w", err)
		}
		f, err := os.Open(path)
		if err != nil {
			return errors.New("goredact dir: cannot open input file")
		}
		stats, scanErr := engine.Redact(ctx, io.Discard, f)
		if scanErr != nil {
			_ = f.Close()
			return safeScanError(scanErr)
		}
		if o.showSecrets {
			if err := loadSecrets(f, fileFindings); err != nil {
				_ = f.Close()
				return errors.New("goredact dir: cannot read matched secret")
			}
		}
		closeErr := f.Close()
		if closeErr != nil {
			return errors.New("goredact dir: cannot close input file")
		}
		report.FilesScanned++
		report.BytesRead += stats.BytesRead
		report.Findings = append(report.Findings, fileFindings...)
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
		if entry.Type().IsRegular() {
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	return paths, err
}
