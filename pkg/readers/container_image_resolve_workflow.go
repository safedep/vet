package readers

import (
	"fmt"
	scalibrlayerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/safedep/vet/pkg/common/logger"
)

type imageResolutionWorkflowFunc func() (*scalibrlayerimage.Image, error)

func (c *containerImageReader) imageFromLocalDockerImageCatalog() (*scalibrlayerimage.Image, error) {
	return nil, nil
}

func (c *containerImageReader) imageFromLocalTarFolder() (*scalibrlayerimage.Image, error) {
	return nil, nil
}

func (c *containerImageReader) imageFromRemoteRegistry() (*scalibrlayerimage.Image, error) {
	logger.Infof("Running workflow imageFromRemoteRegistry")
	if !c.config.RemoteImageFetch {
		return nil, fmt.Errorf("remote image fetching is disabled")
	}

	containerImage, err := scalibrlayerimage.FromRemoteName(c.imageTarget.imageStr, scalibrlayerimage.DefaultConfig())
	if err != nil {
		logger.Errorf("Failed to get Scalibr container image: %s", err)
		return nil, fmt.Errorf("failed to fetch container image: %s", err)
	}
	return containerImage, nil
}
