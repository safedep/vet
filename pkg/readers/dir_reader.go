package readers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

type directoryReader struct {
	path       string
	exclusions []string
}

// NewDirectoryReader creates a [PackageManifestReader] that can scan a directory
// for package manifests while honoring exclusion rules. This reader will log
// and ignore parser failure. But it will fail in case the manifest handler
// returns an error. Exclusion strings are treated as regex patterns and applied
// on the absolute file path discovered while talking the directory.
func NewDirectoryReader(path string,
	exclusions []string) (PackageManifestReader, error) {
	return &directoryReader{
		path:       path,
		exclusions: exclusions,
	}, nil
}

// Name returns the name of this reader
func (p *directoryReader) Name() string {
	return "Directory Based Package Manifest Reader"
}

// EnumManifests discovers package manifests in a directory using conventional
// lockfile names. For each manifest discovered, it invokes the callback handler
// with the manifest model and a default package reader implementation.
func (p *directoryReader) EnumManifests(handler func(*models.PackageManifest,
	PackageReader) error) error {
	err := filepath.WalkDir(p.path, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && p.ignorableDirectory(info.Name()) {
			logger.Debugf("Ignoring directory: %s", path)
			return filepath.SkipDir
		}

		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}

		if p.excludedPath(path) {
			logger.Debugf("Ignoring excluded path: %s", path)
			return filepath.SkipDir
		}

		// We try to find a parser by filename and try to parse it
		// We do not care about error here because not all files are parseable
		p, err := parser.FindParser(path, "")
		if err != nil {
			return nil
		}

		manifest, err := p.Parse(path)
		if err != nil {
			logger.Warnf("Failed to parse: %s due to %v", path, err)
			return nil
		}

		return handler(manifest,
			NewManifestModelReader(manifest))
	})

	return err
}

// TODO: Build a precompiled cache of regex patterns
func (p *directoryReader) excludedPath(path string) bool {
	for _, pattern := range p.exclusions {
		m, err := regexp.MatchString(pattern, path)
		if err != nil {
			logger.Warnf("Invalid regex pattern: %s: %v", pattern, err)
			continue
		}

		if m {
			return true
		}
	}

	return false
}

func (p *directoryReader) ignorableDirectory(name string) bool {
	dirs := []string{
		".git",
		"node_modules",
	}

	for _, d := range dirs {
		if strings.EqualFold(d, name) {
			return true
		}
	}

	return false
}
