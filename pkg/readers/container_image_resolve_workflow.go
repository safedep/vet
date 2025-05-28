package readers

import (
	"errors"
	"fmt"
	scalibrlayerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/safedep/vet/pkg/common/logger"
	"os"
)

type imageResolutionWorkflowFunc func() (*scalibrlayerimage.Image, error)

func (c *containerImageReader) imageFromLocalDockerImageCatalog() (*scalibrlayerimage.Image, error) {
	logger.Infof("using image form local docker image catalog")
	return nil, nil
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
