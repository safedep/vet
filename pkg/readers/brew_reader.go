package readers

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

type brewReader struct {
	config BrewReaderConfig
}

type BrewReaderConfig struct{}

type brewInfo struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Tap      string `json:"tap"`
	Desc     string `json:"desc"`
	License  string `json:"license"`
	Homepage string `json:"homepage"`
	Versions struct {
		Stable string `json:"stable"`
	} `json:"versions"`
	InstalledVersions []struct {
		Version string `json:"version"`
	} `json:"installed"`
}

func NewBrewReader(config BrewReaderConfig) (PackageManifestReader, error) {
	return &brewReader{config: config}, nil
}

func (b *brewReader) ApplicationName() (string, error) {
	return "homebrew", nil
}

func (b *brewReader) Name() string {
	return "Homebrew Reader"
}

func (b *brewReader) EnumManifests(handler func(*models.PackageManifest, PackageReader) error) error {
	cmd := exec.Command("brew", "info", "--installed", "--json")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to execute brew command: %w", err)
	}

	var brewPackages []brewInfo
	if err := json.Unmarshal(output, &brewPackages); err != nil {
		return fmt.Errorf("failed to parse brew JSON output: %w", err)
	}

	manifest := models.NewPackageManifestFromHomebrew()
	// Convert brew info to packages
	for _, brewPkg := range brewPackages {
		version := ""
		for _, installed := range brewPkg.InstalledVersions {
			version = installed.Version
		}
		pkg := &models.Package{
			PackageDetails: lockfile.PackageDetails{
				Name:      brewPkg.FullName,
				Version:   version,
				Ecosystem: lockfile.Ecosystem("brew"),
			},
			Insights: &insightapi.PackageVersionInsight{
				Licenses: &[]insightapi.License{
					insightapi.License(brewPkg.License),
				},
			},
		}
		manifest.AddPackage(pkg)
	}

	return handler(manifest, NewManifestModelReader(manifest))
}
