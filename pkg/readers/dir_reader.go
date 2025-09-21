package readers

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

type DirectoryReaderConfig struct {
	// Path to enumerate
	Path string

	// Exclusions are glob patterns to ignore paths
	Exclusions []string

	// Explicitly walk for the given manifest type. If this is empty
	// directory reader will automatically try to find the suitable
	// parser for a given file
	ManifestTypeOverride string
}

type directoryReader struct {
	config           DirectoryReaderConfig
	exclusionMatcher *exclusionMatcher
}

// NewDirectoryReader creates a [PackageManifestReader] that can scan a directory
// for package manifests while honoring exclusion rules. This reader will log
// and ignore parser failure. But it will fail in case the manifest handler
// returns an error. Exclusion strings are treated as glob patterns and applied
// on the absolute file path discovered while talking the directory.
func NewDirectoryReader(config DirectoryReaderConfig) (PackageManifestReader, error) {
	ex := newPathExclusionMatcher(config.Exclusions)

	return &directoryReader{
		config:           config,
		exclusionMatcher: ex,
	}, nil
}

// Name returns the name of this reader
func (p *directoryReader) Name() string {
	return "Directory Based Package Manifest Reader"
}

func (p *directoryReader) ApplicationName() (string, error) {
	return filepath.Base(p.config.Path), nil
}

// EnumManifests discovers package manifests in a directory using conventional
// lockfile names. For each manifest discovered, it invokes the callback handler
// with the manifest model and a default package reader implementation.
func (p *directoryReader) EnumManifests(handler func(*models.PackageManifest,
	PackageReader) error,
) error {
	// Fail if the root path does not exist
	if _, err := os.Stat(p.config.Path); err != nil {
		return err
	}

	err := filepath.WalkDir(p.config.Path, func(path string, info os.DirEntry, err error) error {
		// We don't fail the entire walk if we cannot access a path
		// This is required when we are scanning a file system and some directories such as .Trash
		// are not accessible
		if err != nil {
			logger.Warnf("Failed to access path %s due to %v", path, err)
			return nil
		}

		if info.IsDir() && p.ignorableDirectory(info.Name()) {
			logger.Debugf("Ignoring directory: %s", path)
			return filepath.SkipDir
		}

		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}

		if p.exclusionMatcher.Match(path) {
			logger.Debugf("Ignoring excluded path: %s", path)
			return filepath.SkipDir
		}

		// We do not want embedded types and extension based resolution
		// for directory based readers because it has higher likelihood
		// of causing surprises and false positives
		lockfile, lockfileAs, err := parser.ResolveParseTarget(path,
			p.config.ManifestTypeOverride,
			[]parser.TargetScopeType{})
		if err != nil {
			return err
		}

		// We try to find a parser by filename and try to parse it
		// We do not care about error here because not all files are parseable
		p, err := parser.FindParser(lockfile, lockfileAs)
		if err != nil {
			return nil
		}

		manifest, err := p.Parse(lockfile)
		if err != nil {
			logger.Warnf("Failed to parse: %s due to %v", path, err)
			return nil
		}

		return handler(manifest,
			NewManifestModelReader(manifest))
	})

	return err
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
