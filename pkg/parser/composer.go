package parser

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/safedep/vet/pkg/models"
)

type ComposerJSON struct {
	Require map[string]string `json:"require"`
}

func parseComposerJSON(path string, config *ParserConfig) (*models.PackageManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open composer.json: %v", err)
	}
	defer file.Close()

	var composerData ComposerJSON
	err = json.NewDecoder(file).Decode(&composerData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %v", err)
	}

	manifest := models.NewPackageManifestFromLocal(path, models.EcosystemPHPComposer)
	for packageName, version := range composerData.Require {
		if packageName == "php" {
			// Skip the PHP version specification itself
			continue
		}

		pkgdetails := models.NewPackageDetail(models.EcosystemPHPComposer, packageName, version)
		packageModel := models.Package{
			PackageDetails: pkgdetails,
			Depth:          0,
		}

		manifest.AddPackage(&packageModel)
	}

	return manifest, nil
}
