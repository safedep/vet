package readers

import (
	"errors"
	"fmt"
	"github.com/docker/distribution/context"
	"github.com/docker/docker/api/types/image"
	scalibrlayerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/safedep/vet/pkg/common/logger"
	"io"
	"os"
	"slices"
)

type imageCleanUpFunc func() error
type imageResolutionWorkflowFunc func() (*scalibrlayerimage.Image, error)

func (c *containerImageReader) imageFromLocalDockerImageCatalog() (*scalibrlayerimage.Image, error) {
	ctx := context.Background()

	allLocalImages, err := c.dockerClient.ImageList(ctx, image.ListOptions{})
	if err != nil {
		logger.Errorf("failed to list images: %s", err)
		return nil, fmt.Errorf("failed to list images: %s", err)
	}

	targetImageId := ""
	for _, image := range allLocalImages {
		if slices.Contains(image.RepoTags, c.imageTarget.imageStr) {
			targetImageId = image.ID
			break
		}
	}

	// no image found
	if targetImageId == "" {
		// not for our workflow
		return nil, nil
	}

	reader, err := c.dockerClient.ImageSave(ctx, []string{targetImageId})
	if err != nil {
		logger.Errorf("failed to save image: %s", err)
		return nil, fmt.Errorf("failed to save image: %s", err)
	}

	// create tem directory in /tmp for storing `POSIX tar archive` in file
	tempTarFile, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("image-%s-*.tar", c.imageTarget.imageStr))

	if err != nil {
		logger.Errorf("failed to create temp file: %s", err)
		return nil, fmt.Errorf("failed to create temp file: %s", err)
	}

	if _, err := io.Copy(tempTarFile, reader); err != nil {
		logger.Errorf("failed to copy docker image data to temp file: %s", err)
		return nil, fmt.Errorf("failed to copy docker image data to temp file: %s", err)
	}

	if err := reader.Close(); err != nil {
		logger.Errorf("failed to close docker save reader: %s", err)
		return nil, fmt.Errorf("failed to close docker save reader: %s", err)
	}
	if err := tempTarFile.Close(); err != nil {
		logger.Errorf("failed to close temp file: %s", err)
		return nil, fmt.Errorf("failed to close temp file: %s", err)
	}

	c.imageTarget.imageStr = tempTarFile.Name()
	image, err := c.imageFromLocalTarFolder()

	if err != nil {
		logger.Errorf("failed to read image from local tar: %s", err)
		return nil, fmt.Errorf("failed to read image from local tar: %s", err)
	}

	logger.Infof("using image form local docker image catalog")
	return image, nil
}

func (c *containerImageReader) imageFromLocalTarFolder() (*scalibrlayerimage.Image, error) {
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

func (c *containerImageReader) imageFromRemoteRegistry() (*scalibrlayerimage.Image, error) {
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
