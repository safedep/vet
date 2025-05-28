package readers

import (
	"context"
	"fmt"

	scalibr "github.com/google/osv-scalibr"
	scalibrlayerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/binary/platform"
	"github.com/google/osv-scalibr/converter"
	el "github.com/google/osv-scalibr/extractor/filesystem/list"
	sl "github.com/google/osv-scalibr/extractor/standalone/list"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

type ContainerImageReaderConfig struct {
	RemoteImageFetch bool
}

func DefaultContainerImageReaderConfig() *ContainerImageReaderConfig {
	return &ContainerImageReaderConfig{
		RemoteImageFetch: true,
	}
}

type imageTargetConfig struct {
	imageStr string
}

type containerImageReader struct {
	config      *ContainerImageReaderConfig
	imageTarget *imageTargetConfig
}

var _ PackageManifestReader = &containerImageReader{}

// NewContainerImageReader fetches images using config and creates containerImageReader
func NewContainerImageReader(imageStr string, config *ContainerImageReaderConfig) (*containerImageReader, error) {
	imageTarget := &imageTargetConfig{
		imageStr: imageStr,
	}
	return &containerImageReader{
		config:      config,
		imageTarget: imageTarget,
	}, nil
}

func (c containerImageReader) Name() string {
	return "Container Image Reader"
}

func (c containerImageReader) ApplicationName() (string, error) {
	return fmt.Sprintf("pkg:/oci/%s", c.imageTarget.imageStr), nil
}

func (c containerImageReader) EnumManifests(handler func(*models.PackageManifest, PackageReader) error) error {
	image, err := c.getScalibrImage(c.imageTarget.imageStr)
	if err != nil {
		logger.Errorf("invalid image: error while creating contaimer image from ref: %s", err)
		return fmt.Errorf("invalid image: error while creating contaimer image from ref: %s", err)
	}

	scanConfig, err := c.getScalibrScanConfig()
	if err != nil {
		logger.Errorf("failed to get scan config: %s", err)
		return fmt.Errorf("failed to get scan config: %s", err)
	}

	// Scan Container
	result, err := scalibr.New().ScanContainer(context.Background(), image, scanConfig)
	if err != nil {
		logger.Errorf("failed to perform container scan: %s", err)
		return fmt.Errorf("failed to perform container scan: %s", err)
	}

	manifests := make(map[string]*models.PackageManifest)

	packagePurlCache := make(map[string]bool)

	for _, pkg := range result.Inventory.Packages {
		pkgPurl := converter.ToPURL(pkg).String()

		// Check if we already added this packages with some-other location (i.e., this package is found somewhere else also)
		if _, ok := packagePurlCache[pkgPurl]; ok {
			// Cache HIT - Continue
			continue
		}

		// Cache MISS
		// Add this into cache
		packagePurlCache[pkgPurl] = true

		key := pkg.Ecosystem()

		for _, location := range pkg.Locations {
			key = fmt.Sprintf("%s:%s", key, location) // Composite like, Go:go/pkg/xyz (EcoSystem:Location)
		}

		if _, ok := manifests[key]; !ok {
			manifests[key] = models.NewPackageManifestFromPurl(pkgPurl, pkg.Ecosystem())
		}

		pkgDetail := models.NewPackageDetail(pkg.Ecosystem(), pkg.Name, pkg.Version)
		pkgPackage := &models.Package{
			PackageDetails: pkgDetail,
			Manifest:       manifests[key],
		}

		manifests[key].AddPackage(pkgPackage)
	}

	// TODO: Some Ecosystem is very bad, like for alpine packages the ecosystem is Alpine2.25,
	for _, manifest := range manifests {
		err = handler(manifest, NewManifestModelReader(manifest))
		if err != nil {
			logger.Errorf("failed to process manifest: %s", err)
			continue
		}
	}

	if err := image.CleanUp(); err != nil {
		logger.Errorf("failed to cleanup image target: %s", err)
		return fmt.Errorf("failed to cleanup image target: %s", err)
	}

	return nil
}

// getScalibrScanConfig returns scalibr.ScanConfig with Extractors and Detectors enabled
func (c *containerImageReader) getScalibrScanConfig() (*scalibr.ScanConfig, error) {
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

	capability := &plugin.Capabilities{
		OS:       plugin.OSAny,
		Network:  plugin.NetworkAny,
		DirectFS: true,
		// From Docs: RunningSystem is "Whether the scanner is scanning the real running system it's on"
		// For Remote Images (Current State), a running system should be false
		// We're scanning a Linux container image whose filesystem is mounted to the host's disk.
		// Ref: https://github.com/google/osv-scalibr/blob/a349e505ba1f0bba00c32d3f2df59807939b3db5/binary/cli/cli.go#L574
		RunningSystem: true,
	}

	// Apply Capabilities
	allFilesystemExtractorsWithCapabilities := el.FilterByCapabilities(allFilesystemExtractors, capability)
	allStandaloneExtractorsWithCapabilities := sl.FilterByCapabilities(allStandaloneExtractors, capability)

	scanRoot, err := c.scalibrDefaultScanRoots()
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

// getScalibrImage converts the user-provided image reference (path, tar, docker image) to a scalibr compatible object
func (c *containerImageReader) getScalibrImage(imageStr string) (*scalibrlayerimage.Image, error) {
	workflow := []imageResolutionWorkflowFunc{
		c.imageFromLocalDockerImageCatalog,
		c.imageFromLocalTarFolder,
		c.imageFromRemoteRegistry,
	}

	for _, getImage := range workflow {
		image, err := getImage()
		if err != nil {
			logger.Errorf("failed to perform workflow: %s", err)
			continue
		}

		if image != nil {
			return image, nil
		}
	}

	logger.Errorf("failed to find image for imageStr: no image resolution workflow applied")
	return nil, fmt.Errorf("failed to find a valid image: no image resolution workflow applied")
}

func (c *containerImageReader) scalibrDefaultScanRoots() ([]*scalibrfs.ScanRoot, error) {
	var scanRoots []*scalibrfs.ScanRoot
	var scanRootPaths []string
	var err error
	if scanRootPaths, err = platform.DefaultScanRoots(false); err != nil {
		return nil, err
	}
	for _, r := range scanRootPaths {
		scanRoots = append(scanRoots, &scalibrfs.ScanRoot{FS: scalibrfs.DirFS(r), Path: r})
	}
	return scanRoots, nil
}
