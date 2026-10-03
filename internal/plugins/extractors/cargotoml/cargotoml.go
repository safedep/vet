// Package cargotoml reads the declared dependencies of a Cargo.toml file
// when the project has no Cargo.lock. Scalibr's cargotoml extractor also
// reports the crate itself and its path dependencies, which are the
// project's own code, as registry packages.
package cargotoml

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
const Name = "rust/cargotoml"

var lockfiles = []string{"Cargo.lock"}

var exactRe = regexp.MustCompile(`^=\s*([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$`)

// sections are the dependency tables of a manifest and their groups.
var sections = map[string][]string{
	"dependencies":       {},
	"build-dependencies": {},
	"dev-dependencies":   {"dev"},
}

// Extractor reads Cargo.toml files in manifest mode.
type Extractor struct{}

// New returns the extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the name of the extractor.
func (Extractor) Name() string { return Name }

// Version returns the version of the extractor.
func (Extractor) Version() int { return 0 }

// Requirements returns the capabilities that the extractor needs.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired selects Cargo.toml files outside the target directory.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	p := api.Path()
	return path.Base(p) == "Cargo.toml" && !slices.Contains(strings.Split(path.Dir(p), "/"), "target")
}

// Extract returns the registry dependencies. A dependency has a version
// only when its requirement pins one with "=". Cargo reads "1.2.3" as
// "^1.2.3", and the lowest version of the range is often years older than
// the version that a build gets. It returns nothing when a Cargo.lock is
// next to the file or in a parent directory. It skips the crate itself and
// path, git and workspace dependencies.
func (Extractor) Extract(_ context.Context, in *filesystem.ScanInput) (inventory.Inventory, error) {
	if locked, err := manifestmode.Locked(in.FS, path.Dir(in.Path), lockfiles); err != nil || locked {
		return inventory.Inventory{}, err
	}
	b, err := io.ReadAll(in.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}
	var doc map[string]any
	if err := toml.Unmarshal(b, &doc); err != nil {
		return inventory.Inventory{}, fmt.Errorf("parse %s: %w", in.Path, err)
	}

	seen := map[string]bool{}
	var pkgs []*extractor.Package
	add := func(table any, groups []string) {
		deps, _ := table.(map[string]any)
		for _, key := range slices.Sorted(maps.Keys(deps)) {
			name, version, ok := dependency(key, deps[key])
			if !ok || seen[name+"@"+version] {
				continue
			}
			seen[name+"@"+version] = true
			pkgs = append(pkgs, &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeCargo,
				Location: extractor.LocationFromPath(in.Path),
				Metadata: &osv.DepGroupMetadata{DepGroupVals: groups},
			})
		}
	}
	for _, sec := range slices.Sorted(maps.Keys(sections)) {
		add(doc[sec], sections[sec])
	}
	if targets, ok := doc["target"].(map[string]any); ok {
		for _, t := range slices.Sorted(maps.Keys(targets)) {
			tt, _ := targets[t].(map[string]any)
			for _, sec := range slices.Sorted(maps.Keys(sections)) {
				add(tt[sec], sections[sec])
			}
		}
	}
	if ws, ok := doc["workspace"].(map[string]any); ok {
		add(ws["dependencies"], []string{})
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// dependency returns the crate name and the lowest version of one entry.
// The entry is a requirement string or a table.
func dependency(key string, v any) (string, string, bool) {
	switch d := v.(type) {
	case string:
		return key, Pinned(d), true
	case map[string]any:
		for _, local := range []string{"path", "git", "workspace"} {
			if _, ok := d[local]; ok {
				return "", "", false
			}
		}
		name := key
		if renamed, ok := d["package"].(string); ok && renamed != "" {
			name = renamed
		}
		req, _ := d["version"].(string)
		return name, Pinned(req), true
	}
	return "", "", false
}

// Pinned returns the version of a requirement that pins one with "=", for
// example "1.2.3" for "=1.2.3", or "".
func Pinned(req string) string {
	if m := exactRe.FindStringSubmatch(strings.TrimSpace(req)); m != nil {
		return m[1]
	}
	return ""
}

var _ filesystem.Extractor = Extractor{}
