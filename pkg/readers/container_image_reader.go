package readers

import (
	"context"
	"fmt"
	scalibr "github.com/google/osv-scalibr"
	scalibrlayerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/extractor"

	//"github.com/google/osv-scalibr/converter"
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
	sl "github.com/google/osv-scalibr/extractor/standalone/list"
	"github.com/safedep/vet/pkg/common/logger"
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
	image, err := c.getScalibrContainerImage()
	if err != nil {
		logger.Errorf("failed to get Scalibr container image: %s", err)
		return fmt.Errorf("failed to get Scalibr container image: %s", err)
	}

	scanConfig, err := c.getScalibrScanConfig()
	if err != nil {
		logger.Errorf("failed to get scan config: %s", err)
		return fmt.Errorf("failed to get Scalibr scan config: %s", err)
	}

	// Scan Container
	result, err := scalibr.New().ScanContainer(context.Background(), image, scanConfig)
	if err != nil {
		logger.Errorf("failed to perform osv-scalibr scan: %s", err)
		return fmt.Errorf("failed to perform osv-scalibr scan: %s", err)
	}

	// Handle duplicated packages as same packages (name+version) are found on different locations.
	// For golang:alpine, 25 % of packages were repeated: the total was 474 with a unique 355
	packageSet := make(map[string]*extractor.Package)

	manifests := make(map[string]*models.PackageManifest)

	for _, pkg := range result.Inventory.Packages {
		pkgPurl := converter.ToPURL(pkg)
		packageSet[pkgPurl.String()] = pkg
	}

	for _, pkg := range packageSet {
		if _, ok := manifests[pkg.Ecosystem()]; !ok {
			manifests[pkg.Ecosystem()] = models.NewPackageManifestFromLocal("", pkg.Ecosystem())
		}

		pkgDetail := models.NewPackageDetail(pkg.Ecosystem(), pkg.Name, pkg.Version)
		pkgPackage := &models.Package{
			PackageDetails: pkgDetail,
			Manifest:       manifests[pkg.Ecosystem()],
		}

		manifests[pkg.Ecosystem()].AddPackage(pkgPackage)
	}

	// TODO: Some Ecosystem is very bad, like for alpine packages the ecosystem is Alpine2.25,
	for _, manifest := range manifests {
		err = handler(manifest, NewManifestModelReader(manifest))
		if err != nil {
			logger.Errorf("failed to process manifest: %s", err)
			return fmt.Errorf("failed to process manifest: %s", err)
		}
	}
	return nil
}

// getScalibrContainerImage returns an Image object from image name string
func (c containerImageReader) getScalibrContainerImage() (*scalibrlayerimage.Image, error) {
	config := scalibrlayerimage.DefaultConfig()
	containerImage, err := scalibrlayerimage.FromRemoteName(c.config.Image, config)
	if err != nil {
		return nil, err
	}
	return containerImage, nil
}

// getScalibrScanConfig returns scalibr.ScanConfig with Extractors and Detectors enabled
func (c containerImageReader) getScalibrScanConfig() (*scalibr.ScanConfig, error) {
	// Create Filesystem Extractors, we are using `all` as in container, we need to find everything
	allFilesystemExtractors, err := el.ExtractorsFromNames([]string{"all"})
	if err != nil {
		return nil, err
	}

	// Create Standalone Extractors, we are using `all` as in container, we need to find everything
	allStandaloneExtractors, err := sl.ExtractorsFromNames([]string{"all"})
	if err != nil {
		return nil, err
	}

	// Get default scalibr capabilities
	capability := parser.ScalibrDefaultCapabilities()

	// From Docs: RunningSystem is "Whether the scanner is scanning the real running system it's on"
	// For Remote Images (Current State), a running system should be false
	// We're scanning a Linux container image whose filesystem is mounted to the host's disk.
	// Ref: https://github.com/google/osv-scalibr/blob/a349e505ba1f0bba00c32d3f2df59807939b3db5/binary/cli/cli.go#L574
	capability.RunningSystem = false

	// Apply Capabilities
	allFilesystemExtractorsWithCapabilities := el.FilterByCapabilities(allFilesystemExtractors, capability)
	allStandaloneExtractorsWithCapabilities := sl.FilterByCapabilities(allStandaloneExtractors, capability)

	scanRoot, err := parser.ScalibrDefaultScanRoots()
	if err != nil {
		return nil, err
	}

	return &scalibr.ScanConfig{
		ScanRoots:            scanRoot,
		FilesystemExtractors: allFilesystemExtractorsWithCapabilities,
		StandaloneExtractors: allStandaloneExtractorsWithCapabilities,
		Capabilities:         capability,
		PathsToExtract:       []string{"."}, // Default
	}, nil
}
