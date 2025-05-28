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

type imageResolutionWorkflowFunc func() (*scalibrlayerimage.Image, error)

func (c containerImageReader) imageFromLocalDockerImageCatalog() (*scalibrlayerimage.Image, error) {
	ctx := context.Background()

	targetImageId, err := c.findLocalDockerImageId(ctx)
	if err != nil {
		return nil, err
	}

	// no image found, go to the next workflow
	if targetImageId == "" {
		return nil, nil
	}

	tempTarFileName, err := c.saveDockerImageToTempFile(ctx, targetImageId)
	if err != nil {
		return nil, err
	}

	// Assign this filename to imageStr of config and use tar image resolver.
	image, err := scalibrlayerimage.FromTarball(tempTarFileName, scalibrlayerimage.DefaultConfig())

	if err != nil {
		return nil, err
	}

	if err := os.Remove(tempTarFileName); err != nil {
		return nil, err
	}

	logger.Infof("using image form local docker image catalog")
	return image, nil
}

func (c containerImageReader) imageFromLocalTarFolder() (*scalibrlayerimage.Image, error) {
	pathExists, err := checkPathExists(c.imageTarget.imageStr)
	if err != nil {
		// Permission denied etc.
		return nil, err
	}

	if !pathExists {
		return nil, nil
	}

	containerImage, err := scalibrlayerimage.FromTarball(c.imageTarget.imageStr, scalibrlayerimage.DefaultConfig())
	if err != nil {
		return nil, err
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
		return nil, err
	}

	logger.Infof("using image form remote registry")
	return containerImage, nil
}

func (c containerImageReader) findLocalDockerImageId(ctx context.Context) (string, error) {
	allLocalImages, err := c.dockerClient.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return "", err
	}

	for _, image := range allLocalImages {
		if slices.Contains(image.RepoTags, c.imageTarget.imageStr) {
			return image.ID, nil
		}
	}

	// no image, without error while finding
	return "", nil
}

func (c containerImageReader) saveDockerImageToTempFile(ctx context.Context, targetImageId string) (string, error) {
	reader, err := c.dockerClient.ImageSave(ctx, []string{targetImageId})
	if err != nil {
		return "", err
	}

	// create tem directory in /tmp for storing `POSIX tar archive` in file
	tempTarFile, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("image-%s-*.tar", c.imageTarget.imageStr))

	if err != nil {
		return "", err
	}

	if _, err := io.Copy(tempTarFile, reader); err != nil {
		return "", err
	}

	if err := reader.Close(); err != nil {
		return "", err
	}

	if err := tempTarFile.Close(); err != nil {
		return "", err
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
