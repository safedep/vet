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

// Package pnpmlock extracts pnpm-lock.yaml files. vet copies it from
// OSV-Scalibr v0.5.3 and adds the dependency edges from the dependencies of
// each package, or of each snapshot in lockfile v9 (decisions D17). The copy
// goes when the upstream pull request merges.
package pnpmlock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/internal/commitextractor"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/internal/graph"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/pnpmlock"
)

type pnpmLockPackageResolution struct {
	Tarball string `yaml:"tarball"`
	Commit  string `yaml:"commit"`
	Repo    string `yaml:"repo"`
	Type    string `yaml:"type"`
}

type pnpmLockPackage struct {
	Resolution           pnpmLockPackageResolution `yaml:"resolution"`
	Name                 string                    `yaml:"name"`
	Version              string                    `yaml:"version"`
	Dev                  bool                      `yaml:"dev"`
	Dependencies         map[string]string         `yaml:"dependencies"`
	OptionalDependencies map[string]string         `yaml:"optionalDependencies"`
}

// pnpmSnapshot holds the dependencies of a package in lockfile v9.
type pnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

// pnpmImporter holds the dependencies of one project of the lockfile. A
// lockfile with one project holds them at the top level.
type pnpmImporter struct {
	Dependencies         map[string]pnpmImporterDep `yaml:"dependencies"`
	DevDependencies      map[string]pnpmImporterDep `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmImporterDep `yaml:"optionalDependencies"`
}

// pnpmImporterDep is the version of a project dependency: a scalar in
// lockfile v5, and a map with "version" in v6 and v9.
type pnpmImporterDep struct {
	Version string
}

// UnmarshalYAML reads the scalar and the map form.
func (d *pnpmImporterDep) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		d.Version = node.Value
		return nil
	}
	var m struct {
		Version string `yaml:"version"`
	}
	if err := node.Decode(&m); err != nil {
		return err
	}
	d.Version = m.Version
	return nil
}

type pnpmLockfile struct {
	Version   float64                    `yaml:"lockfileVersion"`
	Packages  map[string]pnpmLockPackage `yaml:"packages,omitempty"`
	Snapshots map[string]pnpmSnapshot    `yaml:"snapshots,omitempty"`
	Importers map[string]pnpmImporter    `yaml:"importers,omitempty"`
	Root      pnpmImporter               `yaml:",inline"`
}

type pnpmLockfileV6 struct {
	Version   string                     `yaml:"lockfileVersion"`
	Packages  map[string]pnpmLockPackage `yaml:"packages,omitempty"`
	Snapshots map[string]pnpmSnapshot    `yaml:"snapshots,omitempty"`
	Importers map[string]pnpmImporter    `yaml:"importers,omitempty"`
	Root      pnpmImporter               `yaml:",inline"`
}

// UnmarshalYAML is a custom unmarshalling function for handling v6 lockfiles.
func (l *pnpmLockfile) UnmarshalYAML(unmarshal func(any) error) error {
	var lockfileV6 pnpmLockfileV6

	if err := unmarshal(&lockfileV6); err != nil {
		return err
	}

	parsedVersion, err := strconv.ParseFloat(lockfileV6.Version, 64)
	if err != nil {
		return err
	}

	l.Version = parsedVersion
	l.Packages = lockfileV6.Packages
	l.Snapshots = lockfileV6.Snapshots
	l.Importers = lockfileV6.Importers
	l.Root = lockfileV6.Root

	return nil
}

var (
	numberMatcher = regexp.MustCompile(`^\d`)
	// Looks for the pattern "name@version", where name is allowed to contain zero or more "@"
	nameVersionRegexp = regexp.MustCompile(`^(.+)@([\w.-]+)(?:\(|$)`)

	codeLoadURLRegexp = regexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`)
)

// extractPnpmPackageNameAndVersion parses a dependency path, attempting to
// extract the name and version of the package it represents
func extractPnpmPackageNameAndVersion(dependencyPath string, lockfileVersion float64) (string, string, error) {
	// file dependencies must always have a name property to be installed,
	// and their dependency path never has the version encoded, so we can
	// skip trying to extract either from their dependency path
	if strings.HasPrefix(dependencyPath, "file:") {
		return "", "", nil
	}

	// v9.0 specifies the dependencies as <package>@<version> rather than as a path
	if lockfileVersion >= 9.0 {
		dependencyPath = strings.Trim(dependencyPath, "'")
		dependencyPath, isScoped := strings.CutPrefix(dependencyPath, "@")

		name, version, _ := strings.Cut(dependencyPath, "@")

		if isScoped {
			name = "@" + name
		}

		return name, version, nil
	}

	parts := strings.Split(dependencyPath, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid dependency path: %v", dependencyPath)
	}
	var name string

	parts = parts[1:]

	if strings.HasPrefix(parts[0], "@") {
		// A scoped dependency path normally has the form "@scope/name",
		// which splits into two parts. However a malformed path such as
		// "/@scope" leaves a single "@scope" element here, so guard against
		// slicing past the end before joining the scope and name.
		if len(parts) < 2 {
			name = parts[0]
			parts = parts[1:]
		} else {
			name = strings.Join(parts[:2], "/")
			parts = parts[2:]
		}
	} else {
		name = parts[0]
		parts = parts[1:]
	}

	version := ""

	if len(parts) != 0 {
		version = parts[0]
	}

	if version == "" {
		name, version = parseNameAtVersion(name)
	}

	if version == "" || !numberMatcher.MatchString(version) {
		return "", "", nil
	}

	underscoreIndex := strings.Index(version, "_")

	if underscoreIndex != -1 {
		version = strings.Split(version, "_")[0]
	}

	return name, version, nil
}

func parseNameAtVersion(value string) (name string, version string) {
	matches := nameVersionRegexp.FindStringSubmatch(value)

	if len(matches) != 3 {
		return name, ""
	}

	return matches[1], matches[2]
}

func parsePnpmLock(lockfile pnpmLockfile, packageLineMap map[string]int, path string) ([]*extractor.Package, []string, error) {
	packages := make([]*extractor.Package, 0, len(lockfile.Packages))
	keys := make([]string, 0, len(lockfile.Packages))
	errs := []error{}

	for s, pkg := range lockfile.Packages {
		name, version, err := extractPnpmPackageNameAndVersion(s, lockfile.Version)
		if err != nil {
			errs = append(errs, err)
			log.Errorf("failed to extract package version from %v: %v", pkg, err)
			continue
		}

		// "name" is only present if it's not in the dependency path and takes
		// priority over whatever name we think we've extracted (if any)
		if pkg.Name != "" {
			name = pkg.Name
		}

		// "version" is only present if it's not in the dependency path and takes
		// priority over whatever version we think we've extracted (if any)
		if pkg.Version != "" {
			version = pkg.Version
		}

		if name == "" || version == "" {
			continue
		}

		commit := pkg.Resolution.Commit

		if strings.HasPrefix(pkg.Resolution.Tarball, "https://codeload.github.com") {
			matched := codeLoadURLRegexp.FindStringSubmatch(pkg.Resolution.Tarball)

			if matched != nil {
				commit = matched[1]
			}
		}

		repo := ""
		if commit != "" {
			if pkg.Resolution.Repo != "" {
				repo = commitextractor.NormalizeRepo(pkg.Resolution.Repo)
			} else if pkg.Resolution.Tarball != "" {
				repo = commitextractor.NormalizeRepo(pkg.Resolution.Tarball)
			}
		}

		purlType := purl.TypeNPM
		if commit != "" {
			purlType = purl.TypeGit
		}

		depGroups := []string{}
		if pkg.Dev {
			depGroups = append(depGroups, "dev")
		}

		lineNum := packageLineMap[s]
		packages = append(packages, &extractor.Package{
			Name:     name,
			Version:  version,
			PURLType: purlType,
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: commit,
				Repo:   repo,
			},
			Metadata: &osv.DepGroupMetadata{
				DepGroupVals: depGroups,
			},
			Location: extractor.LocationFromPathAndLine(path, lineNum),
		})
		keys = append(keys, name+"@"+version)
	}

	return packages, keys, errors.Join(errs...)
}

// pnpmParents maps the key of each package to the keys of the packages that
// depend on it. Lockfile v9 holds the dependencies in its snapshots, and
// older lockfiles in their packages. The importers are the root project and
// make no edge, so their dependencies become the roots of the graph.
func pnpmParents(lockfile pnpmLockfile) map[string]map[string]bool {
	parents := map[string]map[string]bool{}
	link := func(path, name, version string, deps ...map[string]string) {
		pname, pversion, err := extractPnpmPackageNameAndVersion(path, lockfile.Version)
		if err != nil {
			return
		}
		if name != "" {
			pname = name
		}
		if version != "" {
			pversion = version
		}
		if pname == "" || pversion == "" {
			return
		}
		parent := pname + "@" + trimPeers(pversion)
		for _, group := range deps {
			for child, ref := range group {
				if key, ok := pnpmDependencyKey(child, ref, lockfile.Version); ok {
					graph.Add(parents, key, parent)
				}
			}
		}
	}
	if lockfile.Version >= 9.0 {
		for path, snap := range lockfile.Snapshots {
			link(path, "", "", snap.Dependencies, snap.OptionalDependencies)
		}
		return parents
	}
	for path, pkg := range lockfile.Packages {
		link(path, pkg.Name, pkg.Version, pkg.Dependencies, pkg.OptionalDependencies)
	}
	return parents
}

// pnpmDirect returns the keys of the packages that a project of the
// lockfile requires.
func pnpmDirect(lockfile pnpmLockfile) map[string]bool {
	direct := map[string]bool{}
	for _, imp := range append(slices.Collect(maps.Values(lockfile.Importers)), lockfile.Root) {
		for _, group := range []map[string]pnpmImporterDep{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
			for name, dep := range group {
				if key, ok := pnpmDependencyKey(name, dep.Version, lockfile.Version); ok {
					direct[key] = true
				}
			}
		}
	}
	return direct
}

// pnpmDependencyKey returns the package key of one dependency entry. The
// reference is a version with optional peer suffixes, a dependency path for
// an alias, or a link to a local directory, which is not a package.
func pnpmDependencyKey(name, ref string, lockfileVersion float64) (string, bool) {
	switch {
	case strings.HasPrefix(ref, "link:"), strings.HasPrefix(ref, "file:"):
		return "", false
	case strings.HasPrefix(ref, "/"):
		n, v, err := extractPnpmPackageNameAndVersion(ref, lockfileVersion)
		if err != nil || n == "" || v == "" {
			return "", false
		}
		return n + "@" + trimPeers(v), true
	case !numberMatcher.MatchString(ref):
		n, v := parseNameAtVersion(trimPeers(ref))
		if v == "" {
			return "", false
		}
		return n + "@" + v, true
	}
	return name + "@" + trimPeers(ref), true
}

// trimPeers drops the peer suffix of a version: "(peer@1)" or "_peer@1".
func trimPeers(version string) string {
	version, _, _ = strings.Cut(version, "(")
	version, _, _ = strings.Cut(version, "_")
	return version
}

// Extractor extracts pnpm-lock.yaml files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches pnpm-lock.yaml files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "pnpm-lock.yaml" {
		return false
	}
	// Skip lockfiles inside node_modules directories since the packages they list aren't
	// necessarily installed by the root project. We instead use the more specific top-level
	// lockfile for the root project dependencies.
	dir := filepath.ToSlash(filepath.Dir(path))
	return !slices.Contains(strings.Split(dir, "/"), "node_modules")
}

// Extract extracts packages from a pnpm-lock.yaml file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	dec := yaml.NewDecoder(input.Reader)
	var allPackages []*extractor.Package
	var errs []error

	for {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{Packages: allPackages}, err
		}

		var root yaml.Node
		if err := dec.Decode(&root); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return inventory.Inventory{Packages: allPackages}, fmt.Errorf("could not extract: %w", err)
		}

		var parsedLockfile pnpmLockfile
		if err := root.Decode(&parsedLockfile); err != nil {
			return inventory.Inventory{Packages: allPackages}, fmt.Errorf("could not extract: %w", err)
		}

		packageLineMap := findLineNumbers(&root)

		packages, keys, err := parsePnpmLock(parsedLockfile, packageLineMap, input.Path)
		if err != nil {
			errs = append(errs, err)
		}
		if err := graph.Link(packages, keys, pnpmParents(parsedLockfile), pnpmDirect(parsedLockfile)); err != nil {
			return inventory.Inventory{Packages: allPackages}, err
		}
		allPackages = append(allPackages, packages...)
	}

	if allPackages == nil {
		allPackages = []*extractor.Package{}
	}

	return inventory.Inventory{Packages: allPackages}, errors.Join(errs...)
}

// findLineNumbers goes through the Node tree to find the line numbers for each package.
func findLineNumbers(root *yaml.Node) map[string]int {
	results := make(map[string]int)
	if len(root.Content) == 0 {
		return results
	}
	doc := root.Content[0]

	if doc.Kind != yaml.MappingNode {
		return results // empty results
	}

	var packagesNode *yaml.Node
	// Note: increment by 2 to iterate from key to key (skip the value).
	for i := 0; i < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "packages" {
			packagesNode = doc.Content[i+1]
			break
		}
	}

	if packagesNode == nil || packagesNode.Kind != yaml.MappingNode {
		return results // empty results
	}
	// Note: increment by 2 to iterate from key to key (skip the value).
	for i := 0; i < len(packagesNode.Content); i += 2 {
		keyNode := packagesNode.Content[i]
		results[keyNode.Value] = keyNode.Line
	}
	return results
}

var _ filesystem.Extractor = Extractor{}
