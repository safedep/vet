// Package packagejson reads the declared dependencies of a package.json
// file when the project has no lockfile. Scalibr's packagejson extractor
// reads the package that a package.json describes, and not its
// dependencies (research report, section 3).
package packagejson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Name is the name of the extractor.
const Name = "javascript/packagejsonmanifest"

// lockfiles are the files that make a package.json redundant. The lockfile
// extractor reads the resolved versions.
var lockfiles = []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"}

var semverRe = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?`)

type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// Extractor reads package.json files in manifest mode.
type Extractor struct{}

// New returns the extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the name of the extractor.
func (Extractor) Name() string { return Name }

// Version returns the version of the extractor.
func (Extractor) Version() int { return 0 }

// Requirements returns the capabilities that the extractor needs.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired selects package.json files outside node_modules.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	p := api.Path()
	return path.Base(p) == "package.json" && !slices.Contains(strings.Split(path.Dir(p), "/"), "node_modules")
}

// Extract returns the declared dependencies with the lowest version that
// each range allows. It returns nothing when a lockfile is next to the
// file. A dependency on a file, a URL or a git repository has no registry
// version, so it is skipped.
func (Extractor) Extract(_ context.Context, in *filesystem.ScanInput) (inventory.Inventory, error) {
	dir := path.Dir(in.Path)
	for _, name := range lockfiles {
		_, err := fs.Stat(in.FS, path.Join(dir, name))
		if err == nil {
			return inventory.Inventory{}, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return inventory.Inventory{}, err
		}
	}

	b, err := io.ReadAll(in.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}
	var pj packageJSON
	if err := json.Unmarshal(b, &pj); err != nil {
		return inventory.Inventory{}, fmt.Errorf("parse %s: %w", in.Path, err)
	}

	var pkgs []*extractor.Package
	add := func(deps map[string]string, groups []string) {
		for _, name := range slices.Sorted(maps.Keys(deps)) {
			version, ok := Floor(deps[name])
			if !ok {
				continue
			}
			pkgs = append(pkgs, &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeNPM,
				Location: extractor.LocationFromPath(in.Path),
				Metadata: &osv.DepGroupMetadata{DepGroupVals: groups},
			})
		}
	}
	add(pj.Dependencies, []string{})
	add(pj.DevDependencies, []string{"dev"})
	add(pj.OptionalDependencies, []string{"optional"})
	return inventory.Inventory{Packages: pkgs}, nil
}

// Floor returns the lowest version that an npm range allows, for example
// "4.18.2" for "^4.18.2". It returns false for a range with no version,
// such as "*", or for a file, URL, git or workspace dependency.
func Floor(rng string) (string, bool) {
	rng = strings.TrimSpace(rng)
	if strings.Contains(rng, ":") || strings.Contains(rng, "/") {
		return "", false
	}
	v := semverRe.FindString(rng)
	return v, v != ""
}

var _ filesystem.Extractor = Extractor{}
