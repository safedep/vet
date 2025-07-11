package readers

import (
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestVSCodeExtReaderInit(t *testing.T) {
	reader, err := NewVSIXExtReaderFromDefaultDistributions()
	assert.NoError(t, err)
	assert.NotNil(t, reader)
}

func TestVSCodeExtReaderEnumManifests(t *testing.T) {
	reader, err := NewVSIXExtReader([]string{"./fixtures/vsx"})
	assert.NoError(t, err)
	assert.NotNil(t, reader)

	err = reader.EnumManifests(func(manifest *models.PackageManifest, reader PackageReader) error {
		assert.NotNil(t, manifest)
		assert.NotNil(t, reader)

		assert.Equal(t, 1, manifest.GetPackagesCount())
		assert.Equal(t, "castwide.solargraph", manifest.GetPackages()[0].GetName())
		assert.Equal(t, "0.24.1", manifest.GetPackages()[0].GetVersion())

		return nil
	})

	assert.NoError(t, err)
}
