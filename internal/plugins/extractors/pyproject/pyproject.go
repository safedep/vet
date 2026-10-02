// Package pyproject reads the declared dependencies of a pyproject.toml
// file when the project has no lockfile. Scalibr's pyprojecttoml extractor
// reports the project itself, and not its dependencies.
package pyproject

import (
	"context"
	"fmt"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/manifestmode"
)

// Name is the name of the extractor. It replaces the Scalibr extractor of
// the same name.
const Name = "python/pyprojecttoml"

var lockfiles = []string{"uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "pylock.toml"}

var (
	nameRe   = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$`)
	exactRe  = regexp.MustCompile(`^\s*(===|==)\s*([0-9][0-9A-Za-z.+!-]*)\s*$`)
	poetryRe = regexp.MustCompile(`^\s*([0-9][0-9A-Za-z.+!-]*)\s*$`)
)

type document struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// Extractor reads pyproject.toml files in manifest mode.
type Extractor struct{}

// New returns the extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the name of the extractor.
func (Extractor) Name() string { return Name }

// Version returns the version of the extractor.
func (Extractor) Version() int { return 0 }

// Requirements returns the capabilities that the extractor needs.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired selects pyproject.toml files.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	return path.Base(api.Path()) == "pyproject.toml"
}

// Extract returns the declared dependencies. A dependency has a version
// only when its specifier pins one with "==", as in the requirements
// extractor. The lowest version of a range, such as ">=1.21", is often
// years older than the version that an install gets. It returns nothing
// when a lockfile is next to the file or in a parent directory. It skips
// the project itself and a dependency on a URL.
func (Extractor) Extract(_ context.Context, in *filesystem.ScanInput) (inventory.Inventory, error) {
	if locked, err := manifestmode.Locked(in.FS, path.Dir(in.Path), lockfiles); err != nil || locked {
		return inventory.Inventory{}, err
	}
	b, err := io.ReadAll(in.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}
	var doc document
	if err := toml.Unmarshal(b, &doc); err != nil {
		return inventory.Inventory{}, fmt.Errorf("parse %s: %w", in.Path, err)
	}

	seen := map[string]bool{}
	var pkgs []*extractor.Package
	add := func(name, version string, groups []string) {
		key := strings.ToLower(name) + "@" + version
		if name == "" || seen[key] {
			return
		}
		seen[key] = true
		pkgs = append(pkgs, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purl.TypePyPi,
			Location: extractor.LocationFromPath(in.Path),
			Metadata: &osv.DepGroupMetadata{DepGroupVals: groups},
		})
	}
	addSpecs := func(specs []string, groups []string) {
		for _, s := range specs {
			name, version, ok := Requirement(s)
			if ok {
				add(name, version, groups)
			}
		}
	}

	addSpecs(doc.Project.Dependencies, []string{})
	for _, extra := range slices.Sorted(maps.Keys(doc.Project.OptionalDependencies)) {
		addSpecs(doc.Project.OptionalDependencies[extra], []string{"optional"})
	}
	for _, group := range slices.Sorted(maps.Keys(doc.DependencyGroups)) {
		var specs []string
		for _, item := range doc.DependencyGroups[group] {
			if s, ok := item.(string); ok {
				specs = append(specs, s)
			}
		}
		addSpecs(specs, []string{"dev"})
	}
	addPoetry := func(deps map[string]any, groups []string) {
		for _, name := range slices.Sorted(maps.Keys(deps)) {
			if strings.EqualFold(name, "python") {
				continue
			}
			if version, ok := poetryVersion(deps[name]); ok {
				add(name, version, groups)
			}
		}
	}
	poetry := doc.Tool.Poetry
	addPoetry(poetry.Dependencies, []string{})
	addPoetry(poetry.DevDependencies, []string{"dev"})
	for _, group := range slices.Sorted(maps.Keys(poetry.Group)) {
		groups := []string{"dev"}
		if group == "main" {
			groups = []string{}
		}
		addPoetry(poetry.Group[group].Dependencies, groups)
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// Requirement parses a PEP 508 requirement. It returns the name and the
// pinned version, or no version. It returns false for a requirement on a
// URL.
func Requirement(s string) (string, string, bool) {
	spec, _, _ := strings.Cut(s, ";")
	m := nameRe.FindStringSubmatch(spec)
	if m == nil {
		return "", "", false
	}
	rest := strings.TrimSpace(m[3])
	if strings.HasPrefix(rest, "@") {
		return "", "", false
	}
	rest = strings.Trim(rest, "()")
	if em := exactRe.FindStringSubmatch(rest); em != nil && !strings.Contains(em[2], "*") {
		return m[1], em[2], true
	}
	return m[1], "", true
}

// poetryVersion returns the pinned version of a Poetry dependency. Poetry
// reads a bare version as a pin. It returns false for a path, a git or a
// URL dependency.
func poetryVersion(v any) (string, bool) {
	switch d := v.(type) {
	case string:
		return poetrySpec(d), true
	case map[string]any:
		for _, local := range []string{"path", "git", "url", "file"} {
			if _, ok := d[local]; ok {
				return "", false
			}
		}
		s, _ := d["version"].(string)
		return poetrySpec(s), true
	}
	return "", false
}

func poetrySpec(s string) string {
	if m := poetryRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	if _, v, ok := Requirement("x" + s); ok {
		return v
	}
	return ""
}

var _ filesystem.Extractor = Extractor{}
