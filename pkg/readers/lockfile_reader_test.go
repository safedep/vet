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
		exclusions []string

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
			[]string{},
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
			[]string{},
			nil,
			nil,
			2,
			[]int{3, 13},
		},
		{
			"Lockfile parse with non_standard name",
			[]string{"./fixtures/custom-lockfiles/1-gradle.txt"},
			"gradle.lockfile",
			[]string{},
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
			[]string{},
			nil,
			errors.New("invalid character"),
			0,
			[]int{13},
		},
		{
			"Multiple lockfile parse with exclusion",
			[]string{
				"./fixtures/java/gradle.lockfile",
				"./fixtures/multi-with-invalid/requirements.txt",
			},
			"", // Auto detect from name
			[]string{"./fixtures/multi-with-invalid/requirements.txt"},
			nil,
			nil,
			1,
			[]int{3},
		},
		{
			"Callback returns an error",
			[]string{
				"./fixtures/multi-with-invalid/requirements.txt",
				"./fixtures/java/gradle.lockfile",
			},
			"", // Auto detect from name
			[]string{},
			errors.New("callback error"),
			errors.New("callback error"),
			1,
			[]int{13},
		},
		{
			"Lockfile has non_standard name and no hint",
			[]string{"./a.txt"},
			"",
			[]string{},
			nil,
			errors.New("no parser found"),
			0,
			[]int{},
		},
		{
			"Lockfile does not exists",
			[]string{"./a.txt"},
			"gradle.lockfile",
			[]string{},
			nil,
			errors.New("no such file or directory"),
			0,
			[]int{},
		},
		{
			"Duplicate packages with extras (GitHub issue #343)",
			[]string{"./fixtures/duplicate-packages/requirements.txt"},
			"",
			[]string{},
			nil,
			nil,
			1,
			[]int{2}, // Should have 2 packages (bleach, requests) not 4 duplicates
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			r, err := NewLockfileReader(LockfileReaderConfig{
				Lockfiles:  test.lockfiles,
				LockfileAs: test.lockfileAs,
				Exclusions: test.exclusions,
			})
			assert.Nil(t, err)

			manifestCount := 0
			err = r.EnumManifests(func(m *models.PackageManifest,
				pr PackageReader,
			) error {
				err = pr.EnumPackages(func(pkg *models.Package) error {
					assert.NotNil(t, pkg)
					return nil
				})
				assert.Nil(t, err)

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

func TestLockfileReaderDeduplication(t *testing.T) {
	// Test specifically for GitHub issue #343 - duplicate packages with extras
	t.Run("Deduplicates packages with extras syntax", func(t *testing.T) {

		r, err := NewLockfileReader(LockfileReaderConfig{
			Lockfiles:  []string{"./fixtures/duplicate-packages/requirements.txt"},
			LockfileAs: "",
			Exclusions: []string{},
		})
		assert.Nil(t, err)

		var packages []*models.Package
		err = r.EnumManifests(func(m *models.PackageManifest, pr PackageReader) error {
			packages = m.Packages
			return nil
		})

		assert.Nil(t, err)
		assert.Equal(t, 2, len(packages), "Should have exactly 2 packages after deduplication")

		// Check that we have the expected packages with correct versions
		packageNames := make(map[string]string)
		for _, pkg := range packages {
			packageNames[pkg.PackageDetails.Name] = pkg.PackageDetails.Version
		}

		// Verify bleach has explicit version, not 0.0.0
		assert.Contains(t, packageNames, "bleach")
		assert.Equal(t, "3.1.2", packageNames["bleach"], "bleach should have explicit version 3.1.2")

		// Verify requests has explicit version, not 0.0.0
		assert.Contains(t, packageNames, "requests")
		assert.Equal(t, "2.25.1", packageNames["requests"], "requests should have explicit version 2.25.1")

		// Ensure no 0.0.0 versions remain
		for name, version := range packageNames {
			assert.NotEqual(t, "0.0.0", version, "Package %s should not have unknown version", name)
		}
	})
}
