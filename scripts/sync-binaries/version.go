package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// packageMeta holds the fields from package.json that drive sync decisions.
// Only the fields we actually branch on are declared; json.Unmarshal ignores
// the rest, so the full file content is never disturbed.
type packageMeta struct {
	Private bool     `json:"private"`
	OS      []string `json:"os"`
}

func readPackageMeta(path string) (*packageMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var meta packageMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return &meta, nil
}

// setPackageVersions scans every immediate subdirectory of packagesPath for a
// package.json, skips those with "private": true, and writes version to the
// rest. Returns an error on the first failure.
func setPackageVersions(packagesPath, version string) error {
	if !semverRe.MatchString(version) {
		return fmt.Errorf("invalid version %q: must be x.y.z", version)
	}

	entries, err := os.ReadDir(packagesPath)
	if err != nil {
		return fmt.Errorf("read packages dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(packagesPath, entry.Name(), "package.json")
		if err := setVersionInPackageJSON(path, version); err != nil {
			return fmt.Errorf("package %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// versionFieldRe is used to swap the "version" field in raw JSON bytes instead
// of round-tripping through a Go struct, which would re-serialize arrays and
// destroy inline formatting (e.g. "os": ["linux"] would expand to multi-line).
// Anchoring to start-of-line prevents false matches inside string values of
// other keys. Group 1 captures leading whitespace so indentation is unchanged.
var versionFieldRe = regexp.MustCompile(`(?m)^(\s*)"version"\s*:\s*"[^"]*"`)

// setVersionInPackageJSON reads the file at path, sets "version" to version,
// and writes it back. A missing file is silently skipped. Packages with
// "private": true are skipped unchanged.
//
// The replacement is done on the raw bytes so all other formatting (key order,
// inline arrays, whitespace) is preserved byte-for-byte.
func setVersionInPackageJSON(path, version string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	var meta packageMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if meta.Private {
		return nil
	}

	repl := fmt.Appendf(nil, "${1}\"version\": \"%s\"", version)
	updated := versionFieldRe.ReplaceAll(data, repl)

	// 0o644: package.json must be world-readable for npm tooling.
	return os.WriteFile(path, updated, 0o644) //nolint:gosec
}

// verifyPackageBins checks that every platform package under packagesPath has a
// non-empty bin/ directory. Platform packages are identified by the presence of
// an "os" field in their package.json; packages without that field (e.g. the
// meta/shim package) and private packages are skipped.
func verifyPackageBins(packagesPath string) error {
	entries, err := os.ReadDir(packagesPath)
	if err != nil {
		return fmt.Errorf("read packages dir: %w", err)
	}

	var missing []string

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pkgJSONPath := filepath.Join(packagesPath, entry.Name(), "package.json")
		meta, err := readPackageMeta(pkgJSONPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}

		if meta.Private || len(meta.OS) == 0 {
			continue
		}

		binDir := filepath.Join(packagesPath, entry.Name(), "bin")
		binEntries, err := os.ReadDir(binDir)
		if err != nil || len(binEntries) == 0 {
			missing = append(missing, entry.Name())
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("platform packages missing bin/: %s", strings.Join(missing, ", "))
	}
	return nil
}
