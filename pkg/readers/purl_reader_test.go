package readers

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

// We are not testing the actual parsing here because
// it is handled in the purl package
func TestPurlReader(t *testing.T) {
	reader, err := NewPurlReader("pkg:gem/nokogiri@1.2.3")
	assert.Nil(t, err)

	err = reader.EnumManifests(func(pm *models.PackageManifest, pr PackageReader) error {
		assert.Equal(t, 1, len(pm.Packages))
		assert.NotNil(t, pm.Packages[0])
		assert.Equal(t, "nokogiri", pm.Packages[0].Name)
		assert.Equal(t, "1.2.3", pm.Packages[0].Version)
		assert.Equal(t, lockfile.BundlerEcosystem, pm.Packages[0].Ecosystem)

		return nil
	})

	assert.Nil(t, err)
}
