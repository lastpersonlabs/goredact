package goredact_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestThirdPartyRegisterMatchesGoMod keeps THIRD_PARTY.md honest about what
// the module actually depends on.
//
// The register exists so a licence audit can be re-verified later from the
// recorded tags and URLs. That only works if the recorded release matches
// the required version: a stale entry pins every licence URL to code the
// project no longer ships. The `licence-check` CI job cannot catch this — it
// scans copyright headers, not versions — so this test is the gate.
//
// It requires, for every module in go.mod's require blocks:
//   - an entry whose "Source URL" is the module's repository URL,
//   - a "Release" line matching the required version, and
//   - a "Licence file" URL pinned at that same version.
func TestThirdPartyRegisterMatchesGoMod(t *testing.T) {
	register := readRepoFile(t, "THIRD_PARTY.md")
	entries := parseThirdPartyEntries(t, register)

	requirements := parseGoModRequires(t, readRepoFile(t, "go.mod"))
	if len(requirements) == 0 {
		t.Fatal("parsed no requirements from go.mod")
	}

	for _, req := range requirements {
		url, ok := repositoryURL(req.path)
		if !ok {
			t.Errorf("module %s has no known repository URL form; record it in THIRD_PARTY.md and teach repositoryURL about it", req.path)
			continue
		}
		entry, ok := entries[url]
		if !ok {
			t.Errorf("go.mod requires %s@%s but THIRD_PARTY.md has no entry with Source URL %s", req.path, req.version, url)
			continue
		}
		if entry.release != req.version {
			t.Errorf("THIRD_PARTY.md records %s at %s, go.mod requires %s", req.path, entry.release, req.version)
		}
		if !strings.Contains(entry.licenceURL, "/"+req.version+"/") {
			t.Errorf("THIRD_PARTY.md licence URL for %s is not pinned at %s: %s", req.path, req.version, entry.licenceURL)
		}
	}
}

type moduleRequirement struct {
	path    string
	version string
}

// parseGoModRequires reads both the single-line and block forms of require,
// including entries marked "// indirect": an indirect dependency is still
// linked into the reference CLI and still carries licence obligations.
func parseGoModRequires(t *testing.T, goMod string) []moduleRequirement {
	t.Helper()

	var (
		requirements []moduleRequirement
		inBlock      bool
	)
	single := regexp.MustCompile(`^require\s+(\S+)\s+(\S+)`)
	for _, raw := range strings.Split(goMod, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case line == "require (":
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case inBlock && line != "":
			fields := strings.Fields(line)
			if len(fields) < 2 {
				t.Errorf("unparsable go.mod require line: %q", raw)
				continue
			}
			requirements = append(requirements, moduleRequirement{path: fields[0], version: fields[1]})
		case !inBlock && strings.HasPrefix(line, "require "):
			m := single.FindStringSubmatch(line)
			if m == nil {
				t.Errorf("unparsable go.mod require line: %q", raw)
				continue
			}
			requirements = append(requirements, moduleRequirement{path: m[1], version: m[2]})
		}
	}
	return requirements
}

type thirdPartyEntry struct {
	release    string
	licenceURL string
}

// parseThirdPartyEntries indexes the register by Source URL. Entries without
// a Release line (the adapted-code entries, which record a commit instead)
// are skipped: only module dependencies are version-checked here.
func parseThirdPartyEntries(t *testing.T, register string) map[string]thirdPartyEntry {
	t.Helper()

	entries := make(map[string]thirdPartyEntry)
	var current string
	for _, raw := range strings.Split(register, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "### "):
			current = ""
		case strings.HasPrefix(line, "- Source URL: "):
			current = strings.TrimSuffix(strings.TrimPrefix(line, "- Source URL: "), "/")
		case current != "" && strings.HasPrefix(line, "- Release: "):
			entry := entries[current]
			entry.release = strings.TrimPrefix(line, "- Release: ")
			entries[current] = entry
		case current != "" && strings.HasPrefix(line, "- Licence file: "):
			entry := entries[current]
			entry.licenceURL = strings.TrimPrefix(line, "- Licence file: ")
			entries[current] = entry
		}
	}

	for url, entry := range entries {
		if entry.release == "" {
			delete(entries, url)
		}
	}
	return entries
}

// repositoryURL maps a module path to the repository URL the register
// records. Major-version suffixes (`/v2`, `/v72`) are part of the module
// path but not of the repository URL.
func repositoryURL(modulePath string) (string, bool) {
	parts := strings.Split(modulePath, "/")
	if len(parts) > 1 {
		if last := parts[len(parts)-1]; regexp.MustCompile(`^v[0-9]+$`).MatchString(last) {
			parts = parts[:len(parts)-1]
		}
	}
	if len(parts) != 3 || parts[0] != "github.com" {
		return "", false
	}
	return "https://" + strings.Join(parts, "/"), true
}

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}
