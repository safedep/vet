package readers

import (
	"context"
	"errors"
	"fmt"
	"github.com/docker/docker/api/types/image"
	scalibrlayerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/safedep/vet/pkg/common/logger"
	"io"
	"os"
	"slices"
)

type imageCleanUpFunc func() error
type imageResolutionWorkflowFunc func() (*scalibrlayerimage.Image, error)

func (c containerImageReader) imageFromLocalDockerImageCatalog() (*scalibrlayerimage.Image, error) {
	ctx := context.Background()

	targetImageId, err := c.findLocalDockerImageId(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to find local docker image id: %w", err)
	}

	// no image found, go to the next workflow
	if targetImageId == "" {
		return nil, nil
	}

	tempTarFileName, err := c.saveDockerImageToTempFile(ctx, targetImageId)
	if err != nil {
		return nil, fmt.Errorf("failed to save docker image to temp file: %w", err)
	}

	// Assign this filename to imageStr of config and use tar image resolver.
	c.imageTarget.imageStr = tempTarFileName
	image, err := c.imageFromLocalTarFolder()

	if err != nil {
		logger.Errorf("failed to read image from local tar: %s", err)
		return nil, fmt.Errorf("failed to read image from local tar: %s", err)
	}

	logger.Infof("using image form local docker image catalog")
	return image, nil
}

func (c containerImageReader) imageFromLocalTarFolder() (*scalibrlayerimage.Image, error) {
	pathExists, err := checkPathExists(c.imageTarget.imageStr)
	if err != nil {
		// Permission denied etc.
		logger.Errorf("failed to check tarball %s exists: %s", c.imageTarget.imageStr, err)
		return nil, fmt.Errorf("failed to check tarball %s exists: %s", c.imageTarget.imageStr, err)
	}

	if !pathExists {
		return nil, nil
	}

	containerImage, err := scalibrlayerimage.FromTarball(c.imageTarget.imageStr, scalibrlayerimage.DefaultConfig())
	if err != nil {
		logger.Errorf("failed to get container image from tarball: %s", err)
		return nil, fmt.Errorf("failed to get container image from tarball: %s", err)
	}

	logger.Infof("using image form tarball")
	return containerImage, nil
}

func (c containerImageReader) imageFromRemoteRegistry() (*scalibrlayerimage.Image, error) {
	if !c.config.RemoteImageFetch {
		return nil, fmt.Errorf("remote image fetching is disabled")
	}

	containerImage, err := scalibrlayerimage.FromRemoteName(c.imageTarget.imageStr, scalibrlayerimage.DefaultConfig())
	if err != nil {
		logger.Errorf("Failed to get container image: %s", err)
		return nil, fmt.Errorf("failed to fetch container image: %s", err)
	}

	logger.Infof("using image form remote registry")
	return containerImage, nil
}

func (c containerImageReader) findLocalDockerImageId(ctx context.Context) (string, error) {
	allLocalImages, err := c.dockerClient.ImageList(ctx, image.ListOptions{})
	if err != nil {
		logger.Errorf("failed to list images: %s", err)
		return "", fmt.Errorf("failed to list images: %s", err)
	}

	for _, image := range allLocalImages {
		if slices.Contains(image.RepoTags, c.imageTarget.imageStr) {
			return image.ID, nil
			break
		}
	}

	// no image, without error while finding
	return "", nil
}

func (c containerImageReader) saveDockerImageToTempFile(ctx context.Context, targetImageId string) (string, error) {
	reader, err := c.dockerClient.ImageSave(ctx, []string{targetImageId})
	if err != nil {
		logger.Errorf("failed to save image: %s", err)
		return "", fmt.Errorf("failed to save image: %s", err)
	}

	// create tem directory in /tmp for storing `POSIX tar archive` in file
	tempTarFile, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("image-%s-*.tar", c.imageTarget.imageStr))

	if err != nil {
		logger.Errorf("failed to create temp file: %s", err)
		return "", fmt.Errorf("failed to create temp file: %s", err)
	}

	if _, err := io.Copy(tempTarFile, reader); err != nil {
		logger.Errorf("failed to copy docker image data to temp file: %s", err)
		return "", fmt.Errorf("failed to copy docker image data to temp file: %s", err)
	}

	if err := reader.Close(); err != nil {
		logger.Errorf("failed to close docker save reader: %s", err)
		return "", fmt.Errorf("failed to close docker save reader: %s", err)
	}

	if err := tempTarFile.Close(); err != nil {
		logger.Errorf("failed to close temp file: %s", err)
		return "", fmt.Errorf("failed to close temp file: %s", err)
	}

	// from docs: it is safe to call Name after Close
	return tempTarFile.Name(), nil
}

func checkPathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil // Path exists
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // Path does not exist
	}

	return false, err // other error, like Permission Denied, etc.
}

func saveReadCloserToTempDir(rc io.ReadCloser) (string, string, error) {
	defer rc.Close()

	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "mytempdir-")
	if err != nil {
		return "", "", err
	}
	// Clean up the directory when done: defer os.RemoveAll(tempDir)

	// Create a temporary file inside the directory
	tempFile, err := os.CreateTemp(tempDir, "myfile-*")
	if err != nil {
		return "", "", err
	}
	defer tempFile.Close()

	// Copy the content from the ReadCloser to the file
	_, err = io.Copy(tempFile, rc)
	if err != nil {
		return "", "", err
	}

	// Return the paths for further use
	return tempDir, tempFile.Name(), nil
}
