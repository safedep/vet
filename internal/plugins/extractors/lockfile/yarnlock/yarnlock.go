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

// Package yarnlock extracts NPM yarn.lock files. vet copies it from
// OSV-Scalibr v0.5.3 and adds the dependency edges from the dependencies
// of each entry (decisions D17). The copy goes when the upstream pull
// request merges.
package yarnlock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/commitextractor"
	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/graph"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/yarnlock"
)

var (
	// Version matcher regex.
	// Format for yarn.lock v1: `version "0.0.1"`
	// Format for yarn.lock v2: `version: 0.0.1`
	yarnPackageVersionRe = regexp.MustCompile(`^ {2}"?version"?:? "?([\w-.+]+)"?$`)
	// Package resolution matcher regex. Might contain commit hashes.
	// Format for yarn.lock v1: `resolved "git+ssh://git@github.com:G-Rath/repo-2#hash"`
	// Format for yarn.lock v2: `resolution: "@my-scope/my-first-package@https://github.com/my-org/my-first-pkg.git#commit=hash"`
	yarnPackageResolutionRe = regexp.MustCompile(`^ {2}"?(?:resolution:|resolved)"? "([^ '"]+)"$`)
)

func shouldSkipYarnLine(line string) bool {
	line = strings.TrimSpace(line)
	return line == "" || strings.HasPrefix(line, "#")
}

// yaml.lock files define packages as follows:
//
//	header
//	  prop1 value1
//	  prop2 value2
//
//	header2
//	  prop3 value3
type packageDescription struct {
	header     string
	props      []string
	lineNumber int
}

func groupYarnPackageDescriptions(ctx context.Context, scanner *bufio.Scanner) ([]*packageDescription, error) {
	var result []*packageDescription

	var current *packageDescription
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := scanner.Err(); err != nil {
			return result, err
		}

		line := scanner.Text()

		if shouldSkipYarnLine(line) {
			continue
		}

		// represents the start of a new dependency
		if !strings.HasPrefix(line, " ") {
			// Add previous descriptor if it's for a package.
			if current != nil {
				result = append(result, current)
			}
			current = &packageDescription{header: line, lineNumber: lineNumber}
		} else if current == nil {
			return nil, errors.New("malformed yarn.lock")
		} else {
			current.props = append(current.props, line)
		}
	}
	// Add trailing descriptor.
	if current != nil {
		result = append(result, current)
	}

	return result, nil
}

func extractYarnPackageName(header string) string {
	// Header format: @my-scope/my-first-package@my-scope/my-first-package#commit=hash
	str := strings.TrimPrefix(header, "\"")
	str = strings.TrimSuffix(str, ":")
	str, _, _ = strings.Cut(str, ",")

	isScoped := strings.HasPrefix(str, "@")

	if isScoped {
		str = strings.TrimPrefix(str, "@")
	}
	name, right, _ := strings.Cut(str, "@")

	// Packages can also contain an NPM entry, e.g. @nicolo-ribaudo/chokidar-2@npm:2.1.8-no-fsevents.3
	if strings.HasPrefix(right, "npm:") && strings.Contains(right, "@") {
		return extractYarnPackageName(strings.TrimPrefix(right, "npm:"))
	}

	if isScoped {
		name = "@" + name
	}
	return name
}

func determineYarnPackageVersion(props []string) string {
	for _, s := range props {
		matched := yarnPackageVersionRe.FindStringSubmatch(s)

		if matched != nil {
			return matched[1]
		}
	}
	return ""
}

func determineYarnPackageResolution(props []string) string {
	for _, s := range props {
		matched := yarnPackageResolutionRe.FindStringSubmatch(s)
		if matched != nil {
			return matched[1]
		}
	}
	return ""
}

func parseYarnPackageGroup(desc *packageDescription) *extractor.Package {
	name := extractYarnPackageName(desc.header)
	version := determineYarnPackageVersion(desc.props)
	resolution := determineYarnPackageResolution(desc.props)

	if version == "" {
		log.Errorf("Failed to determine version of %s while parsing a yarn.lock", name)
	}

	purlType := purl.TypeNPM
	commit := commitextractor.TryExtractCommit(resolution)
	var repo string
	if commit != "" {
		purlType = purl.TypeGit
		repo = commitextractor.TryExtractRepo(resolution)
	}

	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purlType,
		SourceCode: &extractor.SourceCodeIdentifier{
			Commit: commit,
			Repo:   repo,
		},
	}
}

// yarnSpecifiers returns the specifiers of an entry header, for example
// ["debug@^4.0.0", "debug@^4.1.0"] for v1 and ["debug@npm:^4.0.0"] for v2.
func yarnSpecifiers(header string) []string {
	header = strings.TrimSuffix(strings.TrimSpace(header), ":")
	var out []string
	for _, spec := range strings.Split(header, ",") {
		if spec = strings.Trim(strings.TrimSpace(spec), `"`); spec != "" {
			out = append(out, spec)
		}
	}
	return out
}

func firstSpecifier(header string) string {
	specs := yarnSpecifiers(header)
	if len(specs) == 0 {
		return ""
	}
	return specs[0]
}

// yarnDependencyKeys returns the package keys of the dependencies and the
// optional dependencies of an entry. A v1 line is `name "range"`, and a v2
// line is `name: range`. A v2 range with no protocol means "npm:".
func yarnDependencyKeys(props []string, keyOf map[string]string) []string {
	var out []string
	inDeps := false
	for _, line := range props {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent <= 2 {
			name := strings.Trim(strings.TrimSuffix(trimmed, ":"), `"`)
			inDeps = name == "dependencies" || name == "optionalDependencies"
			continue
		}
		if !inDeps {
			continue
		}
		name, rng, ok := splitYarnDependency(trimmed)
		if !ok {
			continue
		}
		for _, spec := range []string{name + "@" + rng, name + "@npm:" + rng} {
			if key, found := keyOf[spec]; found {
				out = append(out, key)
				break
			}
		}
	}
	return out
}

func splitYarnDependency(line string) (string, string, bool) {
	var name, rest string
	if strings.HasPrefix(line, `"`) {
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			return "", "", false
		}
		name, rest = line[1:end+1], line[end+2:]
	} else {
		i := strings.IndexAny(line, ": ")
		if i < 0 {
			return "", "", false
		}
		name, rest = line[:i], line[i:]
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, ":"))
	return name, strings.Trim(rest, `"`), name != "" && rest != ""
}

// Extractor extracts NPM yarn.lock files.
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

// FileRequired returns true if the specified file is an NPM yarn.lock file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "yarn.lock" {
		return false
	}
	// Skip lockfiles inside node_modules directories since the packages they list aren't
	// necessarily installed by the root project. We instead use the more specific top-level
	// lockfile for the root project dependencies.
	dir := filepath.ToSlash(filepath.Dir(path))
	return !slices.Contains(strings.Split(dir, "/"), "node_modules")
}

// Extract extracts packages from NPM yarn.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)

	packageGroups, err := groupYarnPackageDescriptions(ctx, scanner)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("error while scanning: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(packageGroups))
	keys := make([]string, 0, len(packageGroups))
	keyOf := map[string]string{}
	var root *packageDescription

	for _, group := range packageGroups {
		if group.header == "__metadata:" {
			// This group doesn't describe a package.
			continue
		}
		if strings.HasSuffix(group.header, "@workspace:.\":") {
			// This is the root package itself.
			root = group
			continue
		}
		pkg := parseYarnPackageGroup(group)
		pkg.Location = extractor.LocationFromPathAndLine(input.Path, group.lineNumber)
		packages = append(packages, pkg)
		key := pkg.Name + "@" + pkg.Version
		keys = append(keys, key)
		for _, spec := range yarnSpecifiers(group.header) {
			keyOf[spec] = key
		}
	}

	parents := map[string]map[string]bool{}
	for _, group := range packageGroups {
		parent, ok := keyOf[firstSpecifier(group.header)]
		if !ok {
			continue
		}
		for _, child := range yarnDependencyKeys(group.props, keyOf) {
			graph.Add(parents, child, parent)
		}
	}
	direct := map[string]bool{}
	if root != nil {
		for _, child := range yarnDependencyKeys(root.props, keyOf) {
			direct[child] = true
		}
	}
	if err := graph.Link(packages, keys, parents, direct); err != nil {
		return inventory.Inventory{}, err
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
