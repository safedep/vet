// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package bunlock extracts bun.lock files
//
// vet copies it from OSV-Scalibr v0.5.3 and adds the dependency edges. Each
// dependency resolves from the install path of the package upward, as Bun
// installs it (decisions D17). The copy goes when the upstream pull request
// merges.
package bunlock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/tidwall/gjson"
	"github.com/tidwall/jsonc"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/commitextractor"
	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/graph"
	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/linefinder"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/bunlock"
)

type bunLockfile struct {
	Version    int                     `json:"lockfileVersion"`
	Workspaces map[string]bunWorkspace `json:"workspaces"`
	Packages   map[string][]any        `json:"packages"`
}

// bunWorkspace holds the dependencies of one workspace of the project.
type bunWorkspace struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// bunDependencies reads the dependency names of a package tuple: the
// object at index 2 with dependencies, optionalDependencies and
// peerDependencies.
func bunDependencies(tuple []any) []string {
	if len(tuple) < 3 {
		return nil
	}
	info, ok := tuple[2].(map[string]any)
	if !ok {
		return nil
	}
	var names []string
	for _, field := range []string{"dependencies", "optionalDependencies", "peerDependencies"} {
		deps, ok := info[field].(map[string]any)
		if !ok {
			continue
		}
		names = append(names, slices.Sorted(maps.Keys(deps))...)
	}
	return names
}

// bunPathNames splits an install path such as "chalk/@scope/x" into its
// package names: ["chalk", "@scope/x"].
func bunPathNames(path string) []string {
	var names []string
	parts := strings.Split(path, "/")
	for i := 0; i < len(parts); i++ {
		if strings.HasPrefix(parts[i], "@") && i+1 < len(parts) {
			names = append(names, parts[i]+"/"+parts[i+1])
			i++
			continue
		}
		names = append(names, parts[i])
	}
	return names
}

// bunResolve returns the install path that a package at from gets for the
// dependency name: the nearest path, from the deepest to the top level.
func bunResolve(packages map[string][]any, from, name string) (string, bool) {
	names := bunPathNames(from)
	if from == "" {
		names = nil
	}
	for i := len(names); i >= 0; i-- {
		candidate := strings.Join(append(slices.Clone(names[:i]), name), "/")
		if _, ok := packages[candidate]; ok {
			return candidate, true
		}
	}
	return "", false
}

// bunGraph returns the parents of each install path and the direct
// install paths, which the workspaces require.
func bunGraph(lock *bunLockfile) (map[string]map[string]bool, map[string]bool) {
	parents := map[string]map[string]bool{}
	for path, tuple := range lock.Packages {
		for _, dep := range bunDependencies(tuple) {
			if child, ok := bunResolve(lock.Packages, path, dep); ok {
				graph.Add(parents, child, path)
			}
		}
	}
	direct := map[string]bool{}
	for _, ws := range lock.Workspaces {
		for _, group := range []map[string]string{ws.Dependencies, ws.DevDependencies, ws.OptionalDependencies} {
			for dep := range group {
				if child, ok := bunResolve(lock.Packages, "", dep); ok {
					direct[child] = true
				}
			}
		}
	}
	return parents, direct
}

// Extractor extracts npm packages from bun.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches bun lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "bun.lock" {
		return false
	}
	// Skip lockfiles inside node_modules directories since the packages they list aren't
	// necessarily installed by the root project. We instead use the more specific top-level
	// lockfile for the root project dependencies.
	dir := filepath.ToSlash(filepath.Dir(path))
	return !slices.Contains(strings.Split(dir, "/"), "node_modules")
}

// structurePackageDetails returns the name, version, commit, and repo of a package
// specified as a tuple in a bun.lock
func structurePackageDetails(pkgs []any) (string, string, string, string, error) {
	if len(pkgs) == 0 {
		return "", "", "", "", errors.New("empty package tuple")
	}

	str, ok := pkgs[0].(string)

	if !ok {
		return "", "", "", "", errors.New("first element of package tuple is not a string")
	}

	str, isScoped := strings.CutPrefix(str, "@")
	name, version, _ := strings.Cut(str, "@")

	if isScoped {
		name = "@" + name
	}

	// url dependencies do not have a semantic version recorded
	if strings.HasPrefix(version, "http://") || strings.HasPrefix(version, "https://") {
		return name, "", "", "", nil
	}

	repo := ""
	version, commit, _ := strings.Cut(version, "#")

	if commit == "" {
		version, commit, _ = strings.Cut(version, "@")
	}

	// bun.lock does not track both the commit and version,
	// so if we have a commit then we don't have a version
	if commit != "" {
		repo = commitextractor.NormalizeRepo(version)
		version = ""
	}

	// file dependencies do not have a semantic version recorded
	if strings.HasPrefix(version, "file:") {
		version = ""
	}

	return name, version, commit, repo, nil
}

// Extract extracts packages from bun.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *bunLockfile

	b, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	if err := json.Unmarshal(jsonc.ToJSON(b), &parsedLockfile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract %w", err)
	}

	finder := linefinder.NewJSONLineFinder(b)
	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))
	keys := make([]string, 0, len(parsedLockfile.Packages))

	var errs []error

	for key, pkg := range parsedLockfile.Packages {
		name, version, commit, repo, err := structurePackageDetails(pkg)
		if err != nil {
			errs = append(errs, fmt.Errorf("could not extract '%s': %w", key, err))

			continue
		}

		purlType := purl.TypeNPM
		if commit != "" {
			purlType = purl.TypeGit
		}

		lineNum := finder.LineOf("packages." + gjson.Escape(key))
		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purlType,
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: commit,
				Repo:   repo,
			},
			Metadata: &osv.DepGroupMetadata{
				DepGroupVals: []string{},
			},
			Location: extractor.LocationFromPathAndLine(input.Path, lineNum),
		})
		keys = append(keys, key)
	}

	parents, direct := bunGraph(parsedLockfile)
	if err := graph.Link(packages, keys, parents, direct); err != nil {
		return inventory.Inventory{}, err
	}
	return inventory.Inventory{Packages: packages}, errors.Join(errs...)
}
