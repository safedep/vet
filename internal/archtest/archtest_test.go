package archtest

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const module = "github.com/safedep/vet/v2"

const safedepAPI = "buf.build/gen/go/safedep/api"

// legacyV1 lists the v1 packages that v2 still keeps as a reference. The
// import rules skip them. Each phase deletes the v1 packages that it
// replaces and removes them from this list. A listed path that does not
// exist fails the test, so the list only shrinks.
var legacyV1 = []string{
	module + "/ent",
	module + "/internal/analytics",
	module + "/pkg",
	module + "/signatures",
}

// publicPackages are the plugin API. They import nothing from internal.
var publicPackages = []string{
	module + "/model",
	module + "/finding",
	module + "/report",
	module + "/plugin",
}

// apiAllowed are the only v2 packages that import the SafeDep API contract.
// The stub server of the acceptance suite speaks it to stand in for SafeDep.
var apiAllowed = []string{
	module + "/internal/plugins/enrichers",
	module + "/internal/plugins/cloud",
	module + "/test/acceptance/stub",
}

type pkgInfo struct {
	path    string
	imports []string
	deps    []string
}

func listPackages(t *testing.T) []pkgInfo {
	t.Helper()

	statSources(t)
	cmd := exec.Command("go", "list", "-f", `{{.ImportPath}}|{{join .Imports ","}}|{{join .Deps ","}}`, module+"/...")
	cmd.Dir = repoRoot(t)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, stderr.String())

	var pkgs []pkgInfo
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "|", 3)
		require.Len(t, parts, 3)
		pkgs = append(pkgs, pkgInfo{path: parts[0], imports: split(parts[1]), deps: split(parts[2])})
	}
	require.NoError(t, sc.Err())
	require.NotEmpty(t, pkgs)
	return pkgs
}

// statSources stats every Go file and go.mod. The test cache then keys on
// them, because "go list" runs in another process that the cache cannot see.
func statSources(t *testing.T) {
	t.Helper()

	root := repoRoot(t)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") || d.Name() == "go.mod" {
			_, err := os.Stat(path)
			return err
		}
		return nil
	})
	require.NoError(t, err)
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, "..", "..")
}

func under(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func underAny(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if under(path, p) {
			return true
		}
	}
	return false
}

func isLegacy(path string) bool {
	return underAny(path, legacyV1)
}

func TestLegacyListOnlyShrinks(t *testing.T) {
	pkgs := listPackages(t)
	for _, prefix := range legacyV1 {
		found := false
		for _, p := range pkgs {
			if under(p.path, prefix) {
				found = true
				break
			}
		}
		assert.True(t, found, "legacy v1 path %s no longer exists: remove it from legacyV1", prefix)
	}
}

func TestPublicPackagesImportNoInternal(t *testing.T) {
	for _, p := range listPackages(t) {
		if !underAny(p.path, publicPackages) {
			continue
		}
		for _, d := range p.deps {
			assert.False(t, under(d, module+"/internal"), "public package %s depends on %s", p.path, d)
		}
	}
}

func TestModelHasNoExtractionOrStorageTypes(t *testing.T) {
	banned := []string{
		"entgo.io/ent",
		"github.com/google/osv-scanner",
		"github.com/google/osv-scalibr",
		safedepAPI,
		module + "/ent",
		module + "/pkg",
	}
	for _, p := range listPackages(t) {
		if !under(p.path, module+"/model") {
			continue
		}
		for _, d := range p.deps {
			assert.False(t, underAny(d, banned), "model package %s depends on %s", p.path, d)
		}
	}
}

func TestOnlyEnrichersAndCloudImportTheAPI(t *testing.T) {
	for _, p := range listPackages(t) {
		if isLegacy(p.path) || underAny(p.path, apiAllowed) {
			continue
		}
		for _, imp := range p.imports {
			assert.False(t, under(imp, safedepAPI), "package %s imports %s", p.path, imp)
		}
	}
}

// TestTUIIsSelfContained keeps internal/tui free to move to dry/tui
// (decisions D15). It imports no vet package outside itself, and no other
// vet package imports dry/tui.
func TestTUIIsSelfContained(t *testing.T) {
	tui := module + "/internal/tui"
	for _, p := range listPackages(t) {
		inside := under(p.path, tui)
		for _, imp := range p.imports {
			if inside {
				assert.False(t, under(imp, module) && !under(imp, tui), "package %s imports %s", p.path, imp)
				continue
			}
			if !isLegacy(p.path) {
				assert.False(t, under(imp, "github.com/safedep/dry/tui"), "package %s imports %s", p.path, imp)
			}
		}
	}
}

// scalibrAllowed are the only v2 packages that import Scalibr. The plugin
// package holds the Extractor alias, and the adapter converts at the
// boundary (package design, section 3.1).
var scalibrAllowed = []string{
	module + "/plugin",
	module + "/internal/plugins/extractors",
	module + "/internal/plugins/sources",
}

func TestOnlyExtractorsImportScalibr(t *testing.T) {
	for _, p := range listPackages(t) {
		if isLegacy(p.path) || underAny(p.path, scalibrAllowed) {
			continue
		}
		for _, imp := range p.imports {
			assert.False(t, under(imp, "github.com/google/osv-scalibr"), "package %s imports %s", p.path, imp)
		}
	}
}
