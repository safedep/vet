package readers

import (
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

const (
	unknownVersion = "0.0.0"
)

type lockfileReader struct {
	config           LockfileReaderConfig
	exclusionMatcher *exclusionMatcher
}

type LockfileReaderConfig struct {
	Lockfiles  []string
	LockfileAs string

	// Exclusions are glob patterns to ignore paths
	Exclusions []string
}

// NewLockfileReader creates a [PackageManifestReader] that can be used to read
// one or more `lockfiles` interpreted as `lockfileAs`. When `lockfileAs` is empty
// the parser auto-detects the format based on file name. This reader fails and
// returns an error on first error encountered while parsing lockfiles
func NewLockfileReader(config LockfileReaderConfig) (PackageManifestReader, error) {
	ex := newPathExclusionMatcher(config.Exclusions)
	return &lockfileReader{
		config:           config,
		exclusionMatcher: ex,
	}, nil
}

// Name returns the name of this reader
func (p *lockfileReader) Name() string {
	return "Lockfiles Based Package Manifest Reader"
}

func (p *lockfileReader) ApplicationName() (string, error) {
	return defaultApplicationName, nil
}

// EnumManifests iterates over the provided lockfile as and attempts to parse
// it as `lockfileAs` parser. To auto-detect parser, set `lockfileAs` to empty
// string during initialization.
func (p *lockfileReader) EnumManifests(handler func(*models.PackageManifest,
	PackageReader) error,
) error {
	for _, lf := range p.config.Lockfiles {
		if p.exclusionMatcher.Match(lf) {
			logger.Debugf("Ignoring excluded path: %s", lf)
			continue
		}

		rf, rt, err := parser.ResolveParseTarget(lf, p.config.LockfileAs,
			[]parser.TargetScopeType{parser.TargetScopeAll})
		if err != nil {
			return err
		}

		lfParser, err := parser.FindParser(rf, rt)
		if err != nil {
			return err
		}

		manifest, err := lfParser.Parse(rf)
		if err != nil {
			return err
		}

		// Check for and filter out duplicate packages without version
		// See GitHub issue #343
		packageMap := make(map[string]*models.Package)
		for _, pkg := range manifest.Packages {
			name := pkg.PackageDetails.Name

			existing, exists := packageMap[name]
			if !exists {
				// Only add if version is not unknown
				if pkg.PackageDetails.Version != unknownVersion && pkg.PackageDetails.Version != "" {
					packageMap[name] = pkg
				}
			} else {
				// Prefer explicit versions over unknown versions
				if pkg.PackageDetails.Version != unknownVersion &&
					pkg.PackageDetails.Version != "" &&
					(existing.PackageDetails.Version == unknownVersion ||
						existing.PackageDetails.Version == "") {
					packageMap[name] = pkg
				}
			}
		}

		// Convert map to slice
		var filteredPkgs []*models.Package
		for _, pkg := range packageMap {
			filteredPkgs = append(filteredPkgs, pkg)
		}

		// Update manifest with filtered packages
		manifest.Packages = filteredPkgs

		// Call the handler with the manifest and a reader for it
		err = handler(manifest, NewManifestModelReader(manifest))
		if err != nil {
			return err
		}
	}

	return nil
}
