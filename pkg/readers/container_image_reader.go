package readers

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/docker/docker/client"
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
	// Pull image from remote registry if not found locally
	RemoteImageFetch bool
}

func DefaultContainerImageReaderConfig() ContainerImageReaderConfig {
	return ContainerImageReaderConfig{
		RemoteImageFetch: true,
	}
}

type imageTargetConfig struct {
	imageRef    string
	isLocalFile bool
}

type containerImageReader struct {
	config       ContainerImageReaderConfig
	imageTarget  imageTargetConfig
	dockerClient *client.Client
}

var _ PackageManifestReader = &containerImageReader{}

// NewContainerImageReader fetches images using config and creates containerImageReader
func NewContainerImageReader(imageRef string, config ContainerImageReaderConfig) (*containerImageReader, error) {
	// docker is not required to be installed for this line, but when we use docker API then it should be.
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	imageTarget := imageTargetConfig{
		imageRef: imageRef,
	}

	if _, err := os.Stat(imageRef); err == nil {
		imageTarget.isLocalFile = true
	}

	return &containerImageReader{
		config:       config,
		imageTarget:  imageTarget,
		dockerClient: dockerClient,
	}, nil
}

func (c containerImageReader) Name() string {
	return "Container Image Reader"
}

func (c containerImageReader) ApplicationName() (string, error) {
	if c.imageTarget.isLocalFile {
		return fmt.Sprintf("file://%s", c.imageTarget.imageRef), nil
	}

	return fmt.Sprintf("pkg:/oci/%s", c.imageTarget.imageRef), nil
}

func (c containerImageReader) EnumManifests(handler func(*models.PackageManifest, PackageReader) error) error {
	ctx := context.Background()

	image, err := c.getScalibrImage(ctx)
	if err != nil {
		return fmt.Errorf("failed to get scalibr image: %w", err)
	}

	scanConfig, err := c.getScalibrScanConfig()
	if err != nil {
		return fmt.Errorf("failed to get scalibr scan config: %w", err)
	}

	// Scan Container
	result, err := scalibr.New().ScanContainer(ctx, image, scanConfig)
	if err != nil {
		return fmt.Errorf("failed to scan container: %w", err)
	}

	manifests := make(map[string]*models.PackageManifest)
	packagePurlCache := make(map[string]bool)

	for _, pkg := range result.Inventory.Packages {
		pkgPurl := converter.ToPURL(pkg).String()

		// Check if we already added this packages with some-other location (i.e., this package is found somewhere else also)
		if _, ok := packagePurlCache[pkgPurl]; ok {
			continue
		}

		packagePurlCache[pkgPurl] = true
		key := pkg.Ecosystem()

		for _, location := range pkg.Locations {
			key = fmt.Sprintf("%s:%s", key, location)
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

	// TODO: We do not recognize some ecosystems, like Alpine2.25
	for _, manifest := range manifests {
		err = handler(manifest, NewManifestModelReader(manifest))
		if err != nil {
			logger.Errorf("failed to process manifest: %s", err)
			continue
		}
	}

	if err := image.CleanUp(); err != nil {
		return fmt.Errorf("failed to clean up image: %w", err)
	}

	return nil
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

	capability := &plugin.Capabilities{
		OS:       plugin.OSAny,
		Network:  plugin.NetworkAny,
		DirectFS: true,
		// From Docs: RunningSystem is "Whether the scanner is scanning the real running system it's on"
		// For Remote Images (Current State), a running system should be false
		// We're scanning a Linux container image whose filesystem is mounted to the host's disk.
		// Ref: https://github.com/google/osv-scalibr/blob/a349e505ba1f0bba00c32d3f2df59807939b3db5/binary/cli/cli.go#L574
		RunningSystem: false,
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
		PathsToExtract:       []string{"."},
	}, nil
}

// getScalibrImage converts the user-provided image reference (path, tar, docker image) to a scalibr compatible object
func (c containerImageReader) getScalibrImage(ctx context.Context) (*scalibrlayerimage.Image, error) {
	// Ordered list of workflows to resolve the image.
	// This also defines the lookup order of the image.
	workflow := []imageResolutionWorkflowFunc{
		c.imageFromLocalTarFile,
		c.imageFromLocalDockerImageCatalog,
		c.imageFromRemoteRegistry,
	}

	for _, getImage := range workflow {
		image, err := getImage(ctx, scalibrlayerimage.DefaultConfig())
		if err != nil {
			if errors.Is(err, imageResolverUnsupportedError) {
				continue
			}

			return nil, fmt.Errorf("invalid image: %w", err)
		}

		if image == nil {
			return nil, fmt.Errorf("invalid image: failed to fetch image")
		}

		// We guarantee that the image is valid before returning.
		// For any other case, we return an error.
		return image, nil
	}

	return nil, fmt.Errorf("invalid image: failed to fetch image")
}

func (c containerImageReader) scalibrDefaultScanRoots() ([]*scalibrfs.ScanRoot, error) {
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
