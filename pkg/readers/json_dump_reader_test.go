package readers

import (
	"errors"
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestJsonDumpReaderEnumManifests(t *testing.T) {
	cases := []struct {
		name string

		// Input
		path string

		// Output
		cbRet error
		err   error

		// Assertions
		manifestCount int
		packageCounts []int
	}{
		{
			"Single JSON file in dump",
			"./fixtures/json-dump-single",
			nil,
			nil,
			1,
			[]int{13},
		},
		{
			"Multiple JSON file in dump",
			"./fixtures/json-dump-multiple",
			nil,
			nil,
			2,
			[]int{3, 13},
		},
		{
			"Callback returns error",
			"./fixtures/json-dump-multiple",
			errors.New("callback error"),
			errors.New("callback error"),
			2,
			[]int{3, 13},
		},
		{
			"Dump directory does not exist",
			"./fixtures/json-dump-does-not-exists",
			nil,
			errors.New("no such file or directory"),
			0,
			[]int{},
		},
		{
			"Dump directory contains invalid JSON",
			"./fixtures/json-dump-with-invalid",
			nil,
			errors.New("invalid manifest error: missing ecosystem"),
			0,
			[]int{0},
		},
	}

	for _, test := range cases {
		r, err := NewJsonDumpReader(test.path)
		assert.Nil(t, err)

		manifestCount := 0
		err = r.EnumManifests(func(m *models.PackageManifest,
			pr PackageReader) error {

			pr.EnumPackages(func(pkg *models.Package) error {
				assert.NotNil(t, pkg)
				return nil
			})

			assert.Equal(t, test.packageCounts[manifestCount], len(m.Packages))
			manifestCount += 1

			return test.cbRet
		})

		if test.err != nil {
			assert.ErrorContains(t, err, test.err.Error())
		} else {
			assert.Nil(t, err)
			assert.Equal(t, test.manifestCount, manifestCount)
		}
	}
}
