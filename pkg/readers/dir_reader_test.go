package readers

import (
	"errors"
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestNewDirectoryReader(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		exclusions []string

		err error
	}{
		{
			"Directory exists",
			"./fixtures/java",
			[]string{},
			nil,
		},
		{
			"Directory does not exists",
			"./fixtures/does.not.exists",
			[]string{},
			nil,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewDirectoryReader(DirectoryReaderConfig{
				Path:       test.path,
				Exclusions: test.exclusions,
			})
			assert.Equal(t, test.err, err)
		})
	}
}

func TestDirectoryReaderEnumPackages(t *testing.T) {
	cases := []struct {
		name string

		// Input
		path       string
		exclusions []string

		// Output
		appName       string
		manifestCount int
		packageCounts []int

		// Callback return value
		cbRet error

		// Test target return value
		err error
	}{
		{
			"Directory enumeration with one manifest",
			"./fixtures/java",
			[]string{},
			"java",
			1,
			[]int{3},
			nil,
			nil,
		},
		{
			"Directory enumeration with multiple manifests",
			"./fixtures/java-multi",
			[]string{},
			"java-multi",
			2,
			// for pom.xml we have 4 dependencies = 1 Direct + 3 Transitive Dependencies
			// Since It's not a lockfile, these transitive dependencies are calculated at runtime
			[]int{3, 4},
			nil,
			nil,
		},
		{
			"Directory enumeration with multiple manifests including invalid",
			"./fixtures/multi-with-invalid",
			[]string{},
			"multi-with-invalid",
			2,
			// for pom.xml we have 4 dependencies = 1 Direct + 3 Transitive Dependencies
			// Since It's not a lockfile, these transitive dependencies are calculated at runtime
			[]int{4, 13},
			nil,
			nil,
		},
		{
			"Directory enumeration with exclusion patterns",
			"./fixtures/multi-with-invalid",
			[]string{"**/requirements.txt"},
			"multi-with-invalid",
			1,
			// for pom.xml we have 4 dependencies = 1 Direct + 3 Transitive Dependencies
			// Since It's not a lockfile, these transitive dependencies are calculated at runtime
			[]int{4},
			nil,
			nil,
		},
		{
			"Directory enumeration must stop if callback returns error",
			"./fixtures/multi-with-invalid",
			[]string{},
			"multi-with-invalid",
			1,
			// for pom.xml we have 4 dependencies = 1 Direct + 3 Transitive Dependencies
			// Since It's not a lockfile, these transitive dependencies are calculated at runtime
			[]int{4},
			errors.New("callback error"),
			errors.New("callback error"),
		},
		{
			"Directory does not exists",
			"./fixtures/does.not.exist",
			[]string{},
			"does.not.exist",
			0,
			[]int{0},
			nil,
			errors.New("lstat ./fixtures/does.not.exist: no such file or directory"),
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			reader, _ := NewDirectoryReader(DirectoryReaderConfig{
				Path:       test.path,
				Exclusions: test.exclusions,
			})
			assert.NotNil(t, reader)

			appName, err := reader.ApplicationName()
			assert.Nil(t, err)
			assert.Equal(t, test.appName, appName)

			manifestCount := 0
			err = reader.EnumManifests(func(m *models.PackageManifest,
				pr PackageReader,
			) error {
				assert.NotNil(t, m)
				assert.NotNil(t, pr)

				assert.Equal(t, test.packageCounts[manifestCount], len(m.Packages))

				manifestCount += 1
				err := pr.EnumPackages(func(pkg *models.Package) error {
					assert.NotNil(t, pkg)
					return nil
				})
				assert.Nil(t, err)

				return test.cbRet
			})

			if test.err != nil {
				assert.ErrorContains(t, test.err, err.Error())
			} else {
				assert.Nil(t, err)
			}

			assert.Equal(t, test.manifestCount, manifestCount)
		})
	}
}

func TestDirectoryReaderExcludedPath(t *testing.T) {
	cases := []struct {
		name         string
		patterns     []string
		matchInput   string
		noMatchInput string
	}{
		{
			"Keyword match",
			[]string{"file.txt"},
			"file.txt",
			"file.json",
		},
		{
			"Wildcard match",
			[]string{"file*"},
			"file.json",
			"not.json",
		},
		{
			"match json in specific recursive subdirectory",
			[]string{"docs/a/**/*.json"},
			"docs/a/sample.json",
			"docs/b/sample.json",
		},
		{
			"match full path json in specific recursive subdirectory",
			[]string{"**/docs/a/**/*.json"},
			"/a/b/docs/a/sample.json",
			"/a/b/docs/b/sample.json",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			m := newPathExclusionMatcher(test.patterns)

			var ret bool
			ret = m.Match(test.matchInput)
			assert.True(t, ret)

			ret = m.Match(test.noMatchInput)
			assert.False(t, ret)
		})
	}
}
