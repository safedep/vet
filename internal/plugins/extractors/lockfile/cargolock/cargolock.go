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

// Package cargolock extracts Cargo.lock files for rust projects. vet copies
// it from OSV-Scalibr v0.5.3 and adds the dependency edges from the
// dependencies of each crate (decisions D17). The copy goes when the
// upstream pull request merges.
package cargolock

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/graph"
	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/lockmeta"
)

const (
	// Name is the unique name of this extractor.
	Name = "rust/cargolock"
)

type cargoLockPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Checksum     string   `toml:"checksum"`
	Dependencies []string `toml:"dependencies"`
}

type cargoLockFile struct {
	Version  int                `toml:"version"`
	Packages []cargoLockPackage `toml:"package"`
}

// Extractor extracts crates.io packages from Cargo.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches Cargo lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Cargo.lock"
}

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Extract extracts packages from Cargo.lock files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *cargoLockFile

	b, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	if _, err := toml.NewDecoder(bytes.NewReader(b)).Decode(&parsedLockfile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packageNames := make([]string, 0, len(parsedLockfile.Packages))
	for _, p := range parsedLockfile.Packages {
		packageNames = append(packageNames, p.Name)
	}
	lineNums := findLineNumbers(b, packageNames)

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))
	for i, lockPackage := range parsedLockfile.Packages {
		var loc extractor.PackageLocation
		if line := lineNums[i]; line > 0 {
			loc = extractor.LocationFromPathAndLine(input.Path, line)
		} else {
			// If no line number found, just record the file path.
			loc = extractor.LocationFromPath(input.Path)
		}

		packages = append(packages, &extractor.Package{
			Name:     lockPackage.Name,
			Version:  lockPackage.Version,
			PURLType: purl.TypeCargo,
			Location: loc,
			// A package with no source is a member of the workspace, or a path
			// dependency.
			Metadata: &lockmeta.Metadata{ResolvedURL: lockPackage.Source, IntegrityHash: lockPackage.Checksum, LocalSource: lockPackage.Source == ""},
		})
	}

	keys := make([]string, len(parsedLockfile.Packages))
	for i, p := range parsedLockfile.Packages {
		keys[i] = p.Name + "@" + p.Version
	}
	parents, direct := cargoParents(parsedLockfile.Packages)
	if err := graph.Link(packages, keys, parents, direct); err != nil {
		return inventory.Inventory{}, err
	}
	return inventory.Inventory{Packages: packages}, nil
}

// cargoParents maps the key of each crate to the keys of the crates that
// depend on it. A dependency is "name", "name version" or "name version
// (source)". A crate with no source is a crate of the workspace. It makes
// no edge, and its dependencies are the direct dependencies.
func cargoParents(pkgs []cargoLockPackage) (map[string]map[string]bool, map[string]bool) {
	versions := map[string][]string{}
	for _, p := range pkgs {
		versions[p.Name] = append(versions[p.Name], p.Version)
	}
	parents := map[string]map[string]bool{}
	direct := map[string]bool{}
	for _, p := range pkgs {
		for _, dep := range p.Dependencies {
			fields := strings.Fields(dep)
			if len(fields) == 0 {
				continue
			}
			name, version := fields[0], ""
			if len(fields) > 1 {
				version = fields[1]
			} else if vs := versions[name]; len(vs) > 0 {
				version = vs[0]
			}
			child := name + "@" + version
			if p.Source == "" {
				direct[child] = true
				continue
			}
			graph.Add(parents, child, p.Name+"@"+p.Version)
		}
	}
	return parents, direct
}

// findLineNumbers returns the line numbers of the specified package names.
//
// This function relies on packageNames being in the same order as they appear in the Cargo.lock
// file. This should be the case for Cargo.lock files parsed with burntsushi/toml.
//
// If a package's line number is not found, the value will be 0.
func findLineNumbers(content []byte, packageNames []string) []int {
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
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		// If the line is a block header, check if it starts a [[package]] block.
		if strings.HasPrefix(line, "[") {
			inPackageBlock = line == "[[package]]"
			continue
		}
		if !inPackageBlock {
			continue
		}

		// Parse the package name.
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != "name" {
			continue
		}
		name := strings.Trim(v, ` "'`)

		// Record the line number if it matches the expected package.
		if name == packageNames[pkgIdx] {
			lineNums[pkgIdx] = lineNum
			pkgIdx++
			inPackageBlock = false // Skip remaining lines in this [[package]] block.
			if pkgIdx == len(packageNames) {
				break
			}
		}
	}

	return lineNums
}

var _ filesystem.Extractor = Extractor{}
