package readers

import (
	"errors"
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestLockfileReaderEnumManifests(t *testing.T) {
	cases := []struct {
		name string

		// Input
		lockfiles  []string
		lockfileAs string

		// Output
		cbRet error
		err   error

		// Assertions
		manifestCount int
		packageCounts []int
	}{
		{
			"Single lockfile parse",
			[]string{"./fixtures/java/gradle.lockfile"},
			"", // Auto detect from name
			nil,
			nil,
			1,
			[]int{3},
		},
		{
			"Multiple lockfile parse",
			[]string{
				"./fixtures/java/gradle.lockfile",
				"./fixtures/multi-with-invalid/requirements.txt",
			},
			"", // Auto detect from name
			nil,
			nil,
			2,
			[]int{3, 13},
		},
		{
			"Lockfile parse with non_standard name",
			[]string{"./fixtures/custom-lockfiles/1-gradle.txt"},
			"gradle.lockfile",
			nil,
			nil,
			1,
			[]int{3},
		},
		{
			"Multiple lockfile parse including invalid",
			[]string{
				"./fixtures/multi-with-invalid/requirements.txt",
				"./fixtures/multi-with-invalid/package-lock.json",
				"./fixtures/java/gradle.lockfile",
			},
			"", // Auto detect from name
			nil,
			errors.New("invalid character"),
			0,
			[]int{13},
		},
		{
			"Callback returns an error",
			[]string{
				"./fixtures/multi-with-invalid/requirements.txt",
				"./fixtures/java/gradle.lockfile",
			},
			"", // Auto detect from name
			errors.New("callback error"),
			errors.New("callback error"),
			1,
			[]int{13},
		},
		{
			"Lockfile has non_standard name and no hint",
			[]string{"./a.txt"},
			"",
			nil,
			errors.New("no parser found"),
			0,
			[]int{},
		},
		{
			"Lockfile does not exists",
			[]string{"./a.txt"},
			"gradle.lockfile",
			nil,
			errors.New("no such file or directory"),
			0,
			[]int{},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			r, err := NewLockfileReader(test.lockfiles, test.lockfileAs)
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
		})
	}
}
