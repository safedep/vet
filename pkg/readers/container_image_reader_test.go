package readers

import (
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestContainerImageReaderEnumManifest(t *testing.T) {
	config := &ContainerImageReaderConfig{
		Image: "alpine:3.20",
	}

	reader, err := NewContainerImageReader(config)
	assert.NoError(t, err)
	assert.NotNil(t, reader)

	err = reader.EnumManifests(func(manifest *models.PackageManifest, reader PackageReader) error {
		assert.NotNil(t, manifest)
		assert.NotNil(t, reader)

		assert.Equal(t, manifest.Ecosystem, "Alpine:v3.20")
		assert.Equal(t, len(manifest.GetPackages()), 14)
		return nil
	})

	assert.NoError(t, err)
}
