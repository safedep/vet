package readers

import (
	"context"
	scalibr "github.com/google/osv-scalibr"
	scalibrlayerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

type ContainerImageReaderConfig struct {
	Image string
}

type containerImageReader struct {
	config *ContainerImageReaderConfig
}

var _ PackageManifestReader = &containerImageReader{}

func NewContainerImageReader(config *ContainerImageReaderConfig) (*containerImageReader, error) {
	return &containerImageReader{
		config: config,
	}, nil
}

func (c containerImageReader) Name() string {
	return "Container Image Reader"
}

func (c containerImageReader) ApplicationName() (string, error) {
	return defaultApplicationName, nil
}

func (c containerImageReader) EnumManifests(handler func(*models.PackageManifest, PackageReader) error) error {
	// Image
	image, err := c.getScalibrContainerImage()
	if err != nil {
		return err
	}

	scanConfig, err := c.getScalibrScanConfig()
	if err != nil {
		return err
	}

	// Scan Container
	result, err := scalibr.New().ScanContainer(context.Background(), image, scanConfig)
	if err != nil {
		return err
	}

	manifests := make(map[string]*models.PackageManifest)

	for _, pkg := range result.Inventory.Packages {
		if _, ok := manifests[pkg.Ecosystem()]; !ok {
			manifests[pkg.Ecosystem()] = models.NewPackageManifestFromPurl(pkg.PURL().String(), pkg.Ecosystem())
		}

		pkgDetail := models.NewPackageDetail(pkg.Ecosystem(), pkg.Name, pkg.Version)
		pkgPackage := &models.Package{
			PackageDetails: pkgDetail,
			Manifest:       manifests[pkg.Ecosystem()],
		}
		manifests[pkg.Ecosystem()].AddPackage(pkgPackage)
	}

	for _, manifest := range manifests {
		err = handler(manifest, NewManifestModelReader(manifest))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c containerImageReader) getScalibrContainerImage() (*scalibrlayerimage.Image, error) {
	config := scalibrlayerimage.DefaultConfig()
	containerImage, err := scalibrlayerimage.FromRemoteName(c.config.Image, config)
	if err != nil {
		return nil, err
	}
	return containerImage, nil
}

func (c containerImageReader) getScalibrScanConfig() (*scalibr.ScanConfig, error) {
	// Create Extractors, we are using `all` as in container, we need to find everything
	allExtractors, err := el.ExtractorsFromNames([]string{"all"})
	if err != nil {
		return nil, err
	}

	// Get default scalibr capabilities
	capability := parser.ScalibrDefaultCapabilities()

	// Apply Capabilities
	allExtractorsWithCapabilities := el.FilterByCapabilities(allExtractors, capability)

	scanRoot, err := parser.ScalibrDefaultScanRoots()
	if err != nil {
		return nil, err
	}

	return &scalibr.ScanConfig{
		ScanRoots:            scanRoot,
		FilesystemExtractors: allExtractorsWithCapabilities,
		Capabilities:         capability,
		PathsToExtract:       []string{"."},
	}, nil
}
