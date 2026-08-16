package main

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
)

func validReportFormat(format string) bool {
	switch format {
	case "json", "csv", "junit", "sarif":
		return true
	default:
		return false
	}
}

func writeReport(name, format string, report scanReport, stdout io.Writer) error {
	dst := stdout
	var file *os.File
	if name != "-" {
		var err error
		file, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("goredact dir: cannot open report output: %w", err)
		}
		dst = file
	}
	var err error
	switch format {
	case "json":
		encoder := json.NewEncoder(dst)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(report)
	case "csv":
		err = writeCSV(dst, report)
	case "junit":
		err = writeJUnit(dst, report)
	case "sarif":
		err = writeSARIF(dst, report)
	}
	if file != nil {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			// Never leave a partial report behind — with -show-secrets it
			// contains secret material (mirrors stream mode's cleanup of
			// its output file on failure).
			_ = os.Remove(name)
		}
	}
	if err != nil {
		return errors.New("goredact dir: cannot write report")
	}
	return nil
}

func writeCSV(dst io.Writer, report scanReport) error {
	w := csv.NewWriter(dst)
	header := []string{"rule_id", "confidence", "file", "start_byte", "end_byte"}
	if report.ShowsSecrets {
		header = append(header, "secret")
	}
	if err := w.Write(header); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		record := []string{finding.RuleID, finding.Confidence, finding.File,
			strconv.FormatInt(finding.StartByte, 10), strconv.FormatInt(finding.EndByte, 10)}
		if report.ShowsSecrets {
			record = append(record, finding.Secret)
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

type junitSuite struct {
	XMLName   xml.Name    `xml:"testsuite"`
	Name      string      `xml:"name,attr"`
	Tests     int         `xml:"tests,attr"`
	Failures  int         `xml:"failures,attr"`
	TestCases []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

func writeJUnit(dst io.Writer, report scanReport) error {
	suite := junitSuite{Name: "goredact", Tests: len(report.Findings), Failures: len(report.Findings)}
	for _, finding := range report.Findings {
		message := findingMessage(finding, report.ShowsSecrets)
		suite.TestCases = append(suite.TestCases, junitCase{Name: finding.RuleID, Classname: finding.File,
			Failure: &junitFailure{Message: message, Text: message}})
	}
	_, err := io.WriteString(dst, xml.Header)
	if err != nil {
		return err
	}
	encoder := xml.NewEncoder(dst)
	encoder.Indent("", "  ")
	if err := encoder.Encode(suite); err != nil {
		return err
	}
	_, err = io.WriteString(dst, "\n")
	return err
}

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	ByteOffset int64 `json:"byteOffset"`
	ByteLength int64 `json:"byteLength"`
}

// sarifFileURI renders a report-relative file path as the percent-encoded
// relative URI SARIF requires: forward slashes regardless of OS, with
// bytes that are invalid in a URI path (spaces, '#', '%') escaped. Strict
// consumers (e.g. GitHub code scanning) reject unescaped URIs.
func sarifFileURI(rel string) string {
	u := url.URL{Path: filepath.ToSlash(rel)}
	return u.EscapedPath()
}

func writeSARIF(dst io.Writer, report scanReport) error {
	results := make([]sarifResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		results = append(results, sarifResult{
			RuleID: finding.RuleID, Level: sarifLevel(finding.Confidence),
			Message: sarifMessage{Text: findingMessage(finding, report.ShowsSecrets)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifFileURI(finding.File)},
				Region:           sarifRegion{ByteOffset: finding.StartByte, ByteLength: finding.EndByte - finding.StartByte},
			}}},
		})
	}
	value := sarifReport{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "goredact"}}, Results: results}}}
	encoder := json.NewEncoder(dst)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func findingMessage(finding reportFinding, showSecret bool) string {
	message := fmt.Sprintf("%s finding at bytes %d-%d", finding.RuleID, finding.StartByte, finding.EndByte)
	if showSecret {
		message += ": " + finding.Secret
	}
	return message
}

func sarifLevel(confidence string) string {
	switch confidence {
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
