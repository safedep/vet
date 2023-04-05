package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

func (s *packageManifestScanner) scanDirectoryForManifests(dir string) ([]*models.PackageManifest, error) {
	var manifests []*models.PackageManifest
	err := filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && s.ignorableDirectory(info.Name()) {
			logger.Debugf("Ignoring directory: %s", path)
			return filepath.SkipDir
		}

		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}

		if s.excludedPath(path) {
			logger.Debugf("Ignoring excluded path: %s", path)
			return filepath.SkipDir
		}

		p, err := parser.FindParser(path, "")
		if err == nil {
			// We have a parseable file
			manifest, err := p.Parse(path)
			if err != nil {
				logger.Warnf("Failed to parse: %s due to %v", path, err)
			} else {
				manifests = append(manifests, &manifest)
			}
		}

		return nil
	})

	return manifests, err
}

func (s *packageManifestScanner) scanLockfilesForManifests(lockfiles []string,
	lockfileAs string) ([]*models.PackageManifest, error) {
	var manifests []*models.PackageManifest
	for _, lf := range lockfiles {
		p, err := parser.FindParser(lf, lockfileAs)
		if err != nil {
			logger.Warnf("Failed to parse %s as %s", lf, lockfileAs)
			continue
		}

		manifest, err := p.Parse(lf)
		if err != nil {
			logger.Warnf("Failed to parse: %s due to %v", lf, err)
			continue
		}

		manifests = append(manifests, &manifest)
	}

	return manifests, nil
}

// TODO: Build a precompiled cache of regex patterns
func (s *packageManifestScanner) excludedPath(path string) bool {
	for _, pattern := range s.config.ExcludePatterns {
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

func (s *packageManifestScanner) ignorableDirectory(name string) bool {
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
