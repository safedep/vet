package parser

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/syft/syft/pkg/cataloger/githubactions"
	"github.com/anchore/syft/syft/source/filesource"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/purl"
	"github.com/safedep/vet/pkg/models"
)

func parseGithubActionWorkflowAsGraph(path string, _ *ParserConfig) (*models.PackageManifest, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if fi.IsDir() {
		return nil, fmt.Errorf("%w: %s is a directory", errUnsupportedFormat, path)
	}

	fs, err := filesource.NewFromPath(path)
	if err != nil {
		return nil, err
	}

	resolver, err := fs.FileResolver("")
	if err != nil {
		return nil, err
	}

	cataloger := githubactions.NewActionUsageCataloger()
	pkgs, _, err := cataloger.Catalog(context.Background(), resolver)
	if err != nil {
		return nil, err
	}

	manifest := models.NewPackageManifestFromLocal(path, models.EcosystemGitHubActions)
	for _, pkg := range pkgs {
		parsedPurl, err := purl.ParsePackageUrl(pkg.PURL)
		if err != nil {
			logger.Errorf("failed to parse package url: %s from file: %s: %v",
				pkg.PURL, path, err)
			continue
		}

		manifest.AddPackage(&models.Package{
			PackageDetails: parsedPurl.GetPackageDetails(),
		})
	}

	return manifest, nil

}
