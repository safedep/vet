package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/safedep/vet/pkg/models"
)

func (s *packageManifestScanner) scanDumpFilesForManifest(dir string) ([]*models.PackageManifest, error) {
	var manifests []*models.PackageManifest
	err := filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var manifest models.PackageManifest
		err = json.Unmarshal(data, &manifest)
		if err != nil {
			return err
		}

		// Fix manifest reference in each package
		for _, pkg := range manifest.Packages {
			pkg.Manifest = &manifest
		}

		manifests = append(manifests, &manifest)
		return nil
	})

	return manifests, err
}
