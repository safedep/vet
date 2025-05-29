package readers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/docker/docker/api/types/image"
	scalibrlayerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/safedep/vet/pkg/common/logger"
)

var imageResolverUnsupportedError = errors.New("image resolver unsupported")

type imageResolutionWorkflowFunc func(ctx context.Context, config *scalibrlayerimage.Config) (*scalibrlayerimage.Image, error)

// imageFromLocalDockerImageCatalog attempts to resolve image from local docker image catalog
func (c containerImageReader) imageFromLocalDockerImageCatalog(ctx context.Context,
	config *scalibrlayerimage.Config,
) (*scalibrlayerimage.Image, error) {
	// Skip if the image is already known to be local
	if c.imageTarget.isLocalFile {
		return nil, imageResolverUnsupportedError
	}

	logger.Debugf("Attempting to resolve image from local docker image catalog: %s", c.imageTarget.imageRef)

	allLocalImages, err := c.dockerClient.ImageList(ctx, image.ListOptions{})
	if err != nil {
		logger.Debugf("Failed to list local images: %s", err.Error())

		// This is not a failure because docker daemon may not be running
		return nil, imageResolverUnsupportedError
	}

	var targetImage *image.Summary
	for _, localImage := range allLocalImages {
		if slices.Contains(localImage.RepoTags, c.imageTarget.imageRef) {
			targetImage = &localImage
			break
		}
	}

	// The image is not found in the local docker image catalog
	if targetImage == nil {
		return nil, imageResolverUnsupportedError
	}

	logger.Debugf("Found image in local docker image catalog with ImageID: %s", targetImage.ID)

	reader, err := c.dockerClient.ImageSave(ctx, []string{targetImage.ID})
	if err != nil {
		return nil, imageResolverUnsupportedError
	}

	defer func() {
		if err := reader.Close(); err != nil {
			logger.Errorf("failed to close image reader: %s", err.Error())
		}
	}()

	tempTarFile, err := os.CreateTemp(os.TempDir(), "image-data-*.tar")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp tar file: %w", err)
	}

	defer func() {
		logger.Debugf("Closing temp tar file and removing it: %s", tempTarFile.Name())

		if err := tempTarFile.Close(); err != nil {
			logger.Errorf("failed to close temp tar file: %s", err.Error())
		}

		if err := os.Remove(tempTarFile.Name()); err != nil {
			logger.Errorf("failed to remove temp tar file: %s", err.Error())
		}
	}()

	logger.Debugf("Copying image to temp tar file: %s", tempTarFile.Name())

	if _, err := io.Copy(tempTarFile, reader); err != nil {
		return nil, fmt.Errorf("failed to copy image to temp tar file: %w", err)
	}

	image, err := scalibrlayerimage.FromTarball(tempTarFile.Name(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to create scalibr image from tarball: %w", err)
	}

	logger.Infof("Using image from local docker image catalog with ImageID: %s", targetImage.ID)
	return image, nil
}

func (c containerImageReader) imageFromLocalTarFile(
	_ context.Context,
	config *scalibrlayerimage.Config,
) (*scalibrlayerimage.Image, error) {
	if !c.imageTarget.isLocalFile {
		return nil, imageResolverUnsupportedError
	}

	logger.Debugf("Attempting to resolve image from local tar file: %s", c.imageTarget.imageRef)

	containerImage, err := scalibrlayerimage.FromTarball(c.imageTarget.imageRef, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create scalibr image from tarball: %w", err)
	}

	logger.Infof("Using image from local tar file: %s", c.imageTarget.imageRef)
	return containerImage, nil
}

func (c containerImageReader) imageFromRemoteRegistry(
	_ context.Context,
	config *scalibrlayerimage.Config,
) (*scalibrlayerimage.Image, error) {
	if !c.config.RemoteImageFetch {
		return nil, imageResolverUnsupportedError
	}

	containerImage, err := scalibrlayerimage.FromRemoteName(c.imageTarget.imageRef, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create scalibr image from remote registry: %w", err)
	}

	logger.Infof("Using image from remote registry: %s", c.imageTarget.imageRef)
	return containerImage, nil
}
