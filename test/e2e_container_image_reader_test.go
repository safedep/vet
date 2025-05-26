package test

import (
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestContainerImageReaderEnumManifest(t *testing.T) {
	imageConfig := &readers.ImageTargetConfig{
		Image: "alpine:3.20",
	}
	readerConfig := readers.DefaultContainerImageReaderConfig()

	reader, err := readers.NewContainerImageReader(imageConfig, readerConfig)
	assert.NoError(t, err)
	assert.NotNil(t, reader)

	err = reader.EnumManifests(func(manifest *models.PackageManifest, reader readers.PackageReader) error {
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
