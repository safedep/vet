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

// Package packagelockjson extracts package-lock.json files. vet copies it
// from OSV-Scalibr v0.5.3 and adds the dependency edges, so that each
// package has the ids of the packages that require it (decisions D17). The
// copy goes when the upstream pull request merges.
package packagelockjson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/tidwall/gjson"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/commitextractor"
	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/graph"
	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/linefinder"
	packagelockjson "github.com/safedep/vet/v2/internal/plugins/extractors/internal/npmlock"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/packagelockjson"

	// noLimitMaxFileSizeBytes is a sentinel value that indicates no limit.
	noLimitMaxFileSizeBytes = int64(0)
)

type packageDetails struct {
	Name      string
	Version   string
	Commit    string
	Repo      string
	DepGroups []string
	Source    metadata.NPMPackageSource
	Line      int
	Parents   map[string]bool
	Direct    bool
}

type npmPackageDetailsMap map[string]packageDetails

// mergeNpmDepsGroups handles merging the dependency groups of packages within the
// NPM ecosystem, since they can appear multiple times in the same dependency tree
//
// the merge happens almost as you'd expect, except that if either given packages
// belong to no groups, then that is the result since it indicates the package
// is implicitly a production dependency.
func mergeNpmDepsGroups(a, b packageDetails) []string {
	// if either group includes no groups, then the package is in the "production" group
	if len(a.DepGroups) == 0 || len(b.DepGroups) == 0 {
		return nil
	}

	combined := make([]string, 0, len(a.DepGroups)+len(b.DepGroups))
	combined = append(combined, a.DepGroups...)
	combined = append(combined, b.DepGroups...)

	slices.Sort(combined)

	return slices.Compact(combined)
}

func sourcePriority(s metadata.NPMPackageSource) int {
	switch s {
	case metadata.PublicRegistry:
		return 3
	case metadata.Other:
		return 2
	case metadata.Local:
		return 1
	default:
		return 0
	}
}

func (pdm npmPackageDetailsMap) add(key string, details packageDetails) {
	existing, ok := pdm[key]

	if ok {
		details.DepGroups = mergeNpmDepsGroups(existing, details)
		if sourcePriority(existing.Source) > sourcePriority(details.Source) {
			details.Source = existing.Source
		}
		details.Direct = details.Direct || existing.Direct
		for k := range existing.Parents {
			if details.Parents == nil {
				details.Parents = map[string]bool{}
			}
			details.Parents[k] = true
		}
	}

	pdm[key] = details
}

func parseNpmLockDependencies(dependencies map[string]packagelockjson.Dependency, finder *linefinder.JSONLineFinder, parentPath string) map[string]packageDetails {
	details := npmPackageDetailsMap{}

	for name, detail := range dependencies {
		currentPath := parentPath + "." + gjson.Escape(name)

		if detail.Dependencies != nil {
			nestedDeps := parseNpmLockDependencies(detail.Dependencies, finder, currentPath+".dependencies")
			for k, v := range nestedDeps {
				details.add(k, v)
			}
		}

		version := detail.Version
		finalVersion := version
		commit := ""
		repo := ""

		// If the package is aliased, get the name and version
		// E.g. npm:string-width@^4.2.0
		if strings.HasPrefix(detail.Version, "npm:") {
			i := strings.LastIndex(detail.Version, "@")
			name = detail.Version[4:i]
			finalVersion = detail.Version[i+1:]
		}

		// we can't resolve a version from a "file:" dependency
		if strings.HasPrefix(detail.Version, "file:") {
			finalVersion = ""
		} else {
			commit = commitextractor.TryExtractCommit(detail.Version)
			if commit == "" && detail.Resolved != "" {
				commit = commitextractor.TryExtractCommit(detail.Resolved)
			}

			// if there is a commit, we want to deduplicate based on that rather than
			// the version (the versions must match anyway for the commits to match)
			//
			// we also don't actually know what the "version" is, so blank it
			if commit != "" {
				finalVersion = ""
				version = commit
				repo = commitextractor.TryExtractRepo(detail.Version)
				if repo == "" && detail.Resolved != "" {
					repo = commitextractor.TryExtractRepo(detail.Resolved)
				}
			}
		}

		line := 0
		if finder != nil {
			line = finder.LineOf(currentPath)
		}

		source := DeterminePackageSource(detail.Resolved, commit)

		details.add(name+"@"+version, packageDetails{
			Name:      name,
			Version:   finalVersion,
			Commit:    commit,
			Repo:      repo,
			DepGroups: detail.DepGroups(),
			Source:    source,
			Line:      line,
		})
	}

	return details
}

func extractNpmPackageName(name string) string {
	maybeScope := path.Base(path.Dir(name))
	pkgName := path.Base(name)

	if strings.HasPrefix(maybeScope, "@") {
		pkgName = maybeScope + "/" + pkgName
	}

	return pkgName
}

// isGit checks if the package was resolved from a git repository or commit.
func isGit(raw, commit string) bool {
	if commit != "" {
		return true
	}
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, "git+") ||
		strings.HasPrefix(lower, "git://") ||
		strings.HasPrefix(lower, "git@") ||
		strings.HasPrefix(lower, "ssh://") ||
		strings.HasPrefix(lower, "github:") ||
		strings.HasPrefix(lower, "gitlab:") ||
		strings.HasPrefix(lower, "bitbucket:") ||
		strings.HasSuffix(lower, ".git") ||
		strings.Contains(lower, ".git#")
}

// isHTTP checks if the raw string is an HTTP or HTTPS URL.
func isHTTP(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")) && u.Host != ""
}

// DeterminePackageSource determines the source of an npm package based on its resolved field and commit.
// If it is an HTTP or HTTPS endpoint containing "npm", it is classified as a public registry.
// Otherwise, if it is an HTTP or git endpoint, it is classified as other.
// Anything else (e.g. local directory, file: protocol) is classified as local.
func DeterminePackageSource(resolved, commit string) metadata.NPMPackageSource {
	if isHTTP(resolved) && strings.Contains(strings.ToLower(resolved), "npm") {
		return metadata.PublicRegistry
	}
	if isHTTP(resolved) || isGit(resolved, commit) {
		return metadata.Other
	}
	return metadata.Local
}

// resolveNpmDependency finds the package-lock.json path that npm loads when the
// package at from requires name: the nearest node_modules/name, walking up the tree.
func resolveNpmDependency(packages map[string]packagelockjson.Package, from, name string) string {
	dir := from
	for {
		candidate := "node_modules/" + name
		if dir != "" {
			candidate = dir + "/node_modules/" + name
		}
		if _, ok := packages[candidate]; ok {
			return candidate
		}
		if dir == "" {
			return ""
		}
		i := strings.LastIndex(dir, "node_modules/")
		if i <= 0 {
			dir = ""
		} else {
			dir = strings.TrimSuffix(dir[:i], "/")
		}
	}
}

func parseNpmLockPackages(packages map[string]packagelockjson.Package, finder *linefinder.JSONLineFinder) map[string]packageDetails {
	details := npmPackageDetailsMap{}
	keyOf := map[string]string{}
	defer linkNpmLockPackages(packages, details, keyOf)

	for namePath, detail := range packages {
		if namePath == "" || detail.Link {
			continue
		}

		finalName := detail.Name
		if finalName == "" {
			finalName = extractNpmPackageName(namePath)
		}

		finalVersion := detail.Version

		commit := commitextractor.TryExtractCommit(detail.Resolved)
		repo := ""
		if commit == "" && detail.Version != "" {
			commit = commitextractor.TryExtractCommit(detail.Version)
		}

		// if there is a commit, we want to deduplicate based on that rather than
		// the version (the versions must match anyway for the commits to match)
		if commit != "" {
			finalVersion = commit
			repo = commitextractor.TryExtractRepo(detail.Resolved)
			if repo == "" && detail.Version != "" {
				repo = commitextractor.TryExtractRepo(detail.Version)
			}
		}

		line := 0
		if finder != nil {
			line = finder.LineOf("packages." + gjson.Escape(namePath))
		}

		source := DeterminePackageSource(detail.Resolved, commit)

		keyOf[namePath] = finalName + "@" + finalVersion
		details.add(finalName+"@"+finalVersion, packageDetails{
			Name:      finalName,
			Version:   detail.Version,
			Commit:    commit,
			Repo:      repo,
			DepGroups: detail.DepGroups(),
			Source:    source,
			Line:      line,
		})
	}

	return details
}

func linkNpmLockPackages(packages map[string]packagelockjson.Package, details npmPackageDetailsMap, keyOf map[string]string) {
	for namePath, detail := range packages {
		if detail.Link {
			continue
		}
		requires := []map[string]string{detail.Dependencies, detail.OptionalDependencies, detail.PeerDependencies}
		if namePath == "" {
			requires = append(requires, detail.DevDependencies)
		}
		for _, deps := range requires {
			for dep := range deps {
				childKey, ok := keyOf[resolveNpmDependency(packages, namePath, dep)]
				if !ok {
					continue
				}
				child := details[childKey]
				if namePath == "" {
					child.Direct = true
				} else {
					if child.Parents == nil {
						child.Parents = map[string]bool{}
					}
					child.Parents[keyOf[namePath]] = true
				}
				details[childKey] = child
			}
		}
	}
}

func parseNpmLock(lockfile packagelockjson.LockFile, finder *linefinder.JSONLineFinder) map[string]packageDetails {
	if lockfile.Packages != nil {
		return parseNpmLockPackages(lockfile.Packages, finder)
	}

	return parseNpmLockDependencies(lockfile.Dependencies, finder, "dependencies")
}

// Extractor extracts npm packages from package-lock.json files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a package-lock.json extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := noLimitMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.JavascriptPackageLockJsonConfig {
		return c.GetJavascriptPackageLockJson()
	})
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches npm lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !slices.Contains([]string{"package-lock.json", "npm-shrinkwrap.json"}, filepath.Base(path)) {
		return false
	}
	// Skip lockfiles inside node_modules directories since the packages they list aren't
	// necessarily installed by the root project. We instead use the more specific top-level
	// lockfile for the root project dependencies.
	dir := filepath.ToSlash(filepath.Dir(path))
	if slices.Contains(strings.Split(dir, "/"), "node_modules") {
		return false
	}

	fileInfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > noLimitMaxFileSizeBytes && fileInfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileInfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileInfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts packages from package-lock.json files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages, err := e.extractPkgLock(ctx, input)

	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}

	return inventory.Inventory{Packages: packages}, err
}

func (e Extractor) extractPkgLock(_ context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	// If both package-lock.json and npm-shrinkwrap.json are present in the root of a project,
	// npm-shrinkwrap.json will take precedence and package-lock.json will be ignored.
	if filepath.Base(input.Path) == "package-lock.json" {
		npmShrinkwrapPath := path.Join(filepath.ToSlash(filepath.Dir(input.Path)), "npm-shrinkwrap.json")
		_, err := input.FS.Open(npmShrinkwrapPath)
		if err == nil {
			return nil, nil
		}
	}

	b, err := io.ReadAll(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not read: %w", err)
	}

	var parsedLockfile *packagelockjson.LockFile
	if err := json.Unmarshal(b, &parsedLockfile); err != nil {
		return nil, fmt.Errorf("could not extract: %w", err)
	}

	if parsedLockfile == nil {
		return nil, errors.New("could not extract: decoded null JSON value")
	}

	finder := linefinder.NewJSONLineFinder(b)

	parsed := parseNpmLock(*parsedLockfile, finder)
	keys := slices.Sorted(maps.Keys(parsed))
	result := make([]*extractor.Package, len(keys))
	idOf := map[string]string{}

	for i, key := range keys {
		pkg := parsed[key]
		if pkg.DepGroups == nil {
			pkg.DepGroups = []string{}
		}

		purlType := purl.TypeNPM
		if pkg.Commit != "" {
			purlType = purl.TypeGit
		}

		result[i] = &extractor.Package{
			Name: pkg.Name,
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: pkg.Commit,
				Repo:   pkg.Repo,
			},
			Version:  pkg.Version,
			PURLType: purlType,
			Metadata: &metadata.JavascriptPackageMetadata{
				DepGroupVals: pkg.DepGroups,
				Source:       pkg.Source,
			},
			Location: extractor.LocationFromPathAndLine(input.Path, pkg.Line),
		}
		if pkg.Direct {
			result[i].Metadata = &graph.Metadata{Protoable: result[i].Metadata, Direct: true}
		}
		id, err := result[i].RequireID()
		if err != nil {
			return nil, err
		}
		idOf[key] = id
	}

	for i, key := range keys {
		for parentKey := range parsed[key].Parents {
			if parentID, ok := idOf[parentKey]; ok {
				if result[i].ParentIDs == nil {
					result[i].ParentIDs = map[string]bool{}
				}
				result[i].ParentIDs[parentID] = true
			}
		}
	}

	return result, nil
}
