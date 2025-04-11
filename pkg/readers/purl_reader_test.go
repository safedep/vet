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

func TestPurlReaderWithMultiplePURLS(t *testing.T) {
	cases := []struct {
		name      string
		purl      string
		ecosystem string
		pkgName   string
		version   string
	}{
		{
			"Maven PURL",
			"pkg:maven/org.apache.commons/commons-lang3@3.8.1",
			"Maven",
			"org.apache.commons:commons-lang3",
			"3.8.1",
		},
		{
			"Maven PURL log4j",
			"pkg:maven/log4j/log4j@1.2.17",
			"Maven",
			"log4j:log4j",
			"1.2.17",
		},
		{
			"Parse a pypi PURL without explicit version",
			"pkg:pypi/requests",
			"PyPI",
			"requests",
			"2.32.3",
		},
		{
			"Parse a npm PURL with @latest version",
			"pkg:npm/express@latest",
			"npm",
			"express",
			"5.1.0",
		},
		{
			"Parse an scoped npm PURL with @latest version",
			"pkg:npm/@kunalsin9h/load-gql@latest",
			"npm",
			"@kunalsin9h/load-gql",
			"1.0.2",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			reader, err := NewPurlReader(test.purl)
			assert.Nil(t, err)

			err = reader.EnumManifests(func(pm *models.PackageManifest, pr PackageReader) error {
				assert.Equal(t, 1, len(pm.Packages))
				assert.NotNil(t, pm.Packages[0])
				assert.Equal(t, test.pkgName, pm.Packages[0].Name)
				assert.GreaterOrEqual(t, pm.Packages[0].Version, test.version)
				assert.Equal(t, test.ecosystem, string(pm.Packages[0].Ecosystem))

				return nil
			})

			assert.Nil(t, err)
		})
	}
}

func TestPurlReaderApplicationName(t *testing.T) {
	cases := []struct {
		name    string
		purl    string
		appName string
		err     bool
	}{
		{
			name:    "valid purl",
			purl:    "pkg:gem/nokogiri@1.2.3",
			appName: "nokogiri",
			err:     false,
		},
		{
			name:    "invalid purl",
			purl:    "invalid-purl",
			appName: "",
			err:     true,
		},
		{
			name:    "empty purl",
			purl:    "",
			appName: "",
			err:     true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			reader, err := NewPurlReader(testCase.purl)
			assert.NoError(t, err)

			appName, err := reader.ApplicationName()
			if testCase.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testCase.appName, appName)
			}
		})
	}
}
