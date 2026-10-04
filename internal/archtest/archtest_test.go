package archtest

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
	module + "/internal/analytics",
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

// packageMessages is the one SafeDep API package that model imports, for
// the ecosystem enum and the wire form of a package version.
const packageMessages = safedepAPI + "/protocolbuffers/go/safedep/messages/package/v1"

// dryIdentity is the dry package that owns the identity rules. Only model
// imports it, so the rules stay behind model.PackageVersion.
const dryIdentity = "github.com/safedep/dry/api/pb"

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
			if under(p.path, module+"/model") && imp == packageMessages {
				continue
			}
			assert.False(t, under(imp, safedepAPI), "package %s imports %s", p.path, imp)
		}
	}
}

// TestOnlyModelImportsTheIdentityRules keeps each ecosystem rule behind
// model.PackageVersion. A package that needs a name, a key or an order asks
// model.
func TestOnlyModelImportsTheIdentityRules(t *testing.T) {
	for _, p := range listPackages(t) {
		if isLegacy(p.path) || under(p.path, module+"/model") {
			continue
		}
		for _, imp := range p.imports {
			assert.NotEqual(t, dryIdentity, imp, "package %s imports %s", p.path, imp)
		}
	}
}

// drySemver orders versions as semver, which is wrong for PyPI, Maven and
// other ecosystems. model.PackageVersion.Compare orders under the rule of
// each ecosystem.
const drySemver = "github.com/safedep/dry/semver"

func TestNoPackageImportsSemverOrder(t *testing.T) {
	for _, p := range listPackages(t) {
		if isLegacy(p.path) {
			continue
		}
		for _, imp := range p.imports {
			assert.NotEqual(t, drySemver, imp, "package %s orders versions with %s. Use model.PackageVersion.Compare", p.path, imp)
		}
	}
}

// TestOnlyAPIClientsSendTheWireForm keeps the raw form of a package version
// on the way to a SafeDep service. Every other package compares the
// canonical form.
func TestOnlyAPIClientsSendTheWireForm(t *testing.T) {
	allowed := append([]string{module + "/model"}, apiAllowed...)
	for path, src := range sourcesOutside(t, allowed) {
		assert.NotContains(t, src, ".RawProto()", "%s sends the wire form of a package", path)
	}
}

// purlIdentity matches a PURL that the code compares or uses as a map key.
// A PURL is for display and for the wire. A name that forms no PURL has an
// empty PURL, so two packages would have the same PURL.
var purlIdentity = regexp.MustCompile(`\.PURL(\(\))?\s*[!=]=\s*[^"\s]|[!=]=\s*[\w.]+\.PURL\b|\[[^\]\n]*\.PURL(\(\))?\]`)

// TestPackagesCompareByKey keeps the identity of a package in
// model.PackageVersion: Equal, Key and NameKey, never the PURL string.
func TestPackagesCompareByKey(t *testing.T) {
	for path, src := range sourcesOutside(t, []string{module + "/model"}) {
		assert.Empty(t, purlIdentity.FindAllString(src, -1), "%s uses a PURL as the identity of a package", path)
	}
}

// sourcesOutside returns the non-test Go files of vet, by path, that are
// not in the allowed packages.
func sourcesOutside(t *testing.T, allowed []string) map[string]string {
	t.Helper()
	root := repoRoot(t)
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		pkg := module + "/" + filepath.ToSlash(rel)
		if underAny(pkg, allowed) || isLegacy(pkg) {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = string(src)
		return nil
	})
	require.NoError(t, err)
	return out
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

// Only internal/spdxlicense reads SPDX license expressions. A second reader
// would compare licenses with other rules, such as a deprecated id or an
// or-later term.
func TestOnlySPDXLicenseImportsGoSPDX(t *testing.T) {
	for _, p := range listPackages(t) {
		if isLegacy(p.path) || under(p.path, module+"/internal/spdxlicense") {
			continue
		}
		for _, imp := range p.imports {
			assert.False(t, under(imp, "github.com/github/go-spdx"), "package %s imports %s", p.path, imp)
		}
	}
}

// pluginListAllowed are the only packages that import both the control
// plugins and the sinks. A package that imports both usually lists every
// plugin by hand, and that list goes stale. Read internal/plugins/builtin
// in its place. The runner builds a scan, so it needs both.
var pluginListAllowed = []string{
	module + "/internal/plugins/builtin",
	module + "/internal/runner",
}

func TestOneListOfBuiltinPlugins(t *testing.T) {
	controls, sinks := module+"/internal/plugins/controls", module+"/internal/plugins/sinks"
	for _, p := range listPackages(t) {
		if isLegacy(p.path) || slices.Contains(pluginListAllowed, p.path) {
			continue
		}
		assert.False(t, slices.Contains(p.imports, controls) && slices.Contains(p.imports, sinks),
			"package %s imports the controls and the sinks: read the plugin list from internal/plugins/builtin", p.path)
	}
}
