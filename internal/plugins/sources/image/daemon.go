package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	layerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/moby/moby/client"
	"github.com/safedep/dry/log"
)

// fromDaemon reads an image from the local Docker daemon. Docker resolves
// the reference as the user wrote it. scalibr has
// FromLocalDockerImage, but it makes its temporary file name from the image
// name, so a name with a "/" fails, and it logs on stderr.
func fromDaemon(ctx context.Context, ref string, cfg *layerimage.Config) (*layerimage.Image, error) {
	if _, err := name.ParseReference(ref); err != nil {
		return nil, err
	}
	c, err := client.New(client.FromEnv)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := c.Close(); err != nil {
			log.Debugf("image: close the Docker client: %v", err)
		}
	}()
	if _, err := c.ImageInspect(ctx, ref); err != nil {
		return nil, err
	}
	path, err := save(ctx, c, ref)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := os.Remove(path); err != nil {
			log.Warnf("image: remove %s: %v", path, err)
		}
	}()
	return layerimage.FromTarball(path, cfg)
}

func save(ctx context.Context, c *client.Client, ref string) (string, error) {
	in, err := c.ImageSave(ctx, []string{ref})
	if err != nil {
		return "", err
	}
	defer func() {
		if err := in.Close(); err != nil {
			log.Debugf("image: close the image stream: %v", err)
		}
	}()
	f, err := os.CreateTemp("", "vet-image-*.tar")
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(f, in)
	if err := errors.Join(copyErr, f.Close()); err != nil {
		return "", errors.Join(fmt.Errorf("save image %s: %w", ref, err), os.Remove(f.Name()))
	}
	return f.Name(), nil
}
