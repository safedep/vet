package exceptions

import (
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestNewExceptionsFileLoader(t *testing.T) {
	cases := []struct {
		name      string
		file      string
		ecosystem string
		pkgName   string
		version   string
		match     bool
		errMsg    string
	}{
		{
			"Load a file and match",
			"fixtures/1_valid.yml",
			"maven",
			"p1",
			"v1",
			true,
			"",
		},
		{
			"Match any version",
			"fixtures/1_valid.yml",
			"maven",
			"p2",
			"v5-anything",
			true,
			"",
		},
		{
			"Does not match expired exceptions",
			"fixtures/1_valid.yml",
			"maven",
			"p3",
			"v5-anything",
			false,
			"",
		},
		{
			"Error loading file that does not exist",
			"fixtures/1_does_not_exists.yml",
			"",
			"",
			"",
			false,
			"no such file or directory",
		},
		{
			"Error loading invalid YAML file",
			"fixtures/2_invalid.yml",
			"",
			"",
			"",
			false,
			"unknown field",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			initStore()

			loader, err := NewExceptionsFileLoader(test.file)
			if test.errMsg != "" {
				assert.NotNil(t, err)
				assert.ErrorContains(t, err, test.errMsg)
				return
			}

			Load(loader)

			pd := models.NewPackageDetail(test.ecosystem, test.pkgName, test.version)
			res, _ := Apply(&models.Package{PackageDetails: pd})

			assert.Equal(t, test.match, res.Matched())
		})
	}
}
