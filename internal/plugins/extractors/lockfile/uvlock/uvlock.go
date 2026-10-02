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

// Package uvlock extracts uv.lock files. vet copies it from OSV-Scalibr
// v0.5.3 and adds the dependency edges from the dependencies of each
// package (decisions D17). The copy goes when the upstream pull request
// merges.
package uvlock

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/internal/graph"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/uvlock"
)

type uvLockPackageSource struct {
	Virtual string `toml:"virtual"`
	Git     string `toml:"git"`
}

type uvLockPackage struct {
	Name         string              `toml:"name"`
	Version      string              `toml:"version"`
	Source       uvLockPackageSource `toml:"source"`
	Dependencies []uvDependency      `toml:"dependencies"`
	// DevDependencies holds the dependency groups of the project.
	DevDependencies map[string][]uvDependency `toml:"dev-dependencies"`

	// uv stores "groups" as a table under "package" after all the packages, which due
	// to how TOML works means it ends up being a property on the last package, even
	// through in this context it's a global property rather than being per-package
	Groups map[string][]uvOptionalDependency `toml:"optional-dependencies"`
}

type uvOptionalDependency struct {
	Name string `toml:"name"`
}

// uvDependency is one requirement of a package. Version is set when the
// lockfile holds more than one version of the name.
type uvDependency struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}
type uvLockFile struct {
	Version  int             `toml:"version"`
	Packages []uvLockPackage `toml:"package"`
}

// Extractor extracts python packages from uv.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches uv lockfile patterns
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "uv.lock"
}

// Extract extracts packages from uv.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read file: %w", err)
	}

	var parsedLockfile uvLockFile
	if err := toml.Unmarshal(content, &parsedLockfile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packageNames := make([]string, 0, len(parsedLockfile.Packages))
	for _, p := range parsedLockfile.Packages {
		packageNames = append(packageNames, p.Name)
	}
	lineNums := findPackageLineNumbers(content, packageNames)

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))
	keys := make([]string, 0, len(parsedLockfile.Packages))

	var groups map[string][]uvOptionalDependency

	// uv stores "groups" as a table under "package" after all the packages, which due
	// to how TOML works means it ends up being a property on the last package, even
	// through in this context it's a global property rather than being per-package
	if len(parsedLockfile.Packages) > 0 {
		groups = parsedLockfile.Packages[len(parsedLockfile.Packages)-1].Groups
	}

	for i, lockPackage := range parsedLockfile.Packages {
		// skip including the root "package", since its name and version are most likely arbitrary
		if lockPackage.Source.Virtual == "." {
			continue
		}

		_, commit, _ := strings.Cut(lockPackage.Source.Git, "#")

		pkgDetails := &extractor.Package{
			Name:     lockPackage.Name,
			Version:  lockPackage.Version,
			PURLType: purl.TypePyPi,
			Location: extractor.LocationFromPathAndLine(input.Path, lineNums[i]),
		}

		if commit != "" {
			pkgDetails.SourceCode = &extractor.SourceCodeIdentifier{
				Commit: commit,
			}
		}

		depGroupVals := []string{}

		for group, deps := range groups {
			for _, dep := range deps {
				if dep.Name == lockPackage.Name {
					depGroupVals = append(depGroupVals, group)
				}
			}
		}

		sort.Strings(depGroupVals)

		pkgDetails.Metadata = &osv.DepGroupMetadata{
			DepGroupVals: depGroupVals,
		}
		packages = append(packages, pkgDetails)
		keys = append(keys, lockPackage.Name+"@"+lockPackage.Version)
	}

	parents, direct := uvParents(parsedLockfile.Packages)
	if err := graph.Link(packages, keys, parents, direct); err != nil {
		return inventory.Inventory{}, err
	}
	return inventory.Inventory{Packages: packages}, nil
}

// uvParents maps the key of each package to the keys of the packages that
// require it. The virtual root project is a parent key with no package. Its
// requirements are the direct dependencies.
func uvParents(pkgs []uvLockPackage) (map[string]map[string]bool, map[string]bool) {
	versions := map[string][]string{}
	for _, p := range pkgs {
		versions[p.Name] = append(versions[p.Name], p.Version)
	}
	resolve := func(d uvDependency) (string, bool) {
		if d.Version != "" {
			return d.Name + "@" + d.Version, true
		}
		vs := versions[d.Name]
		if len(vs) == 0 {
			return "", false
		}
		return d.Name + "@" + vs[0], true
	}

	parents := map[string]map[string]bool{}
	direct := map[string]bool{}
	for _, p := range pkgs {
		parent := p.Name + "@" + p.Version
		deps := p.Dependencies
		for _, group := range p.Groups {
			for _, d := range group {
				deps = append(deps, uvDependency{Name: d.Name})
			}
		}
		for _, group := range p.DevDependencies {
			deps = append(deps, group...)
		}
		for _, d := range deps {
			child, ok := resolve(d)
			if !ok {
				continue
			}
			if p.Source.Virtual == "." {
				direct[child] = true
			}
			graph.Add(parents, child, parent)
		}
	}
	return parents, direct
}

// extractPackageName parses a TOML key-value line and returns the unquoted
// package name if the key is "name". Returns false if the line is not a valid name assignment.
// TODO(b/491518484): Put in common location for all Python extractors to use.
func extractPackageName(line string) (string, bool) {
	if !strings.HasPrefix(line, "name") {
		return "", false
	}

	k, _, ok := strings.Cut(line, "=")
	if !ok || strings.TrimSpace(k) != "name" {
		return "", false
	}

	var pkg uvLockPackage
	if err := toml.Unmarshal([]byte(line), &pkg); err != nil {
		return "", false
	}

	return pkg.Name, true
}

// findPackageLineNumbers returns an array of line numbers that correspond to the array of package
// names passed in.
func findPackageLineNumbers(content []byte, packageNames []string) []int {
	lineNums := make([]int, len(packageNames))
	if len(packageNames) == 0 {
		return lineNums
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	pkgIdx := 0
	inPackageBlock := false
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			inPackageBlock = true
			continue
		}

		if inPackageBlock && strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[package]]") {
			inPackageBlock = false
			continue
		}

		if !inPackageBlock || pkgIdx >= len(packageNames) {
			continue
		}

		extractedName, ok := extractPackageName(line)
		if !ok || extractedName != packageNames[pkgIdx] {
			continue
		}

		lineNums[pkgIdx] = lineNum
		pkgIdx++
		inPackageBlock = false

		if pkgIdx == len(packageNames) {
			break
		}
	}

	return lineNums
}

var _ filesystem.Extractor = Extractor{}
