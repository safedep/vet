package readers

import (
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestContainerImageReaderEnumManifest(t *testing.T) {
	imageConfig := &ImageTargetConfig{
		Image: "alpine:3.20",
	}
	readerConfig := DefaultContainerImageReaderConfig()

	reader, err := NewContainerImageReader(imageConfig, readerConfig)
	assert.NoError(t, err)
	assert.NotNil(t, reader)

	err = reader.EnumManifests(func(manifest *models.PackageManifest, reader PackageReader) error {
		assert.NotNil(t, manifest)
		assert.NotNil(t, reader)

		manifestID := manifest.Id()

		assert.Equal(t, manifest.Ecosystem, "Alpine:v3.20")
		assert.Equal(t, len(manifest.GetPackages()), 14)
		assert.Equal(t, manifest.GetPackages()[0].Manifest.Id(), manifestID)
		return nil
	})

	assert.NoError(t, err)
}
