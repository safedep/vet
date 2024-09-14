package parser

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/source/filesource"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/purl"
	"github.com/safedep/vet/pkg/models"
)

func parseJavaArchiveAsGraph(path string, config *ParserConfig) (*models.PackageManifest, error) {
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

	cataloger := java.NewArchiveCataloger(java.DefaultArchiveCatalogerConfig())
	pkgs, _, err := cataloger.Catalog(context.Background(), resolver)
	if err != nil {
		return nil, err
	}

	manifest := models.NewPackageManifest(path, models.EcosystemMaven)
	for _, pkg := range pkgs {
		parsedPurl, err := purl.ParsePackageUrl(pkg.PURL)
		if err != nil {
			logger.Errorf("failed to parse package url: %s from jar: %s", pkg.PURL, path)
			continue
		}

		manifest.AddPackage(&models.Package{
			PackageDetails: parsedPurl.GetPackageDetails(),
		})
	}

	return manifest, nil
}
