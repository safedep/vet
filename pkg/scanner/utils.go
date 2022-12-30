package scanner

import (
	"os"
	"path/filepath"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

func scanDirectoryForManifests(dir string) ([]*models.PackageManifest, error) {
	var manifests []*models.PackageManifest
	err := filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}

		path, err = filepath.Abs(path)
		if err != nil {
			return err
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

func scanLockfilesForManifests(lockfiles []string, lockfileAs string) ([]*models.PackageManifest, error) {
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
