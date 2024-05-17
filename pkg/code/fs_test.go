package code

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAcceptableSourceFile(t *testing.T) {
	cases := []struct {
		name          string
		path          string
		excludedGlobs []string
		includedGlobs []string
		want          bool
	}{
		{
			"No globs",
			"/a/b/foo.go",
			[]string{},
			[]string{},
			true,
		},
		{
			"Excluded glob",
			"/a/b/foo.go",
			[]string{"*.go"},
			[]string{},
			false,
		},
		{
			"Included glob",
			"/a/b/foo.go",
			[]string{},
			[]string{"*.go"},
			true,
		},
		{
			"Excluded and included globs",
			"/a/b/foo.go",
			[]string{"*.go"},
			[]string{"*.go"},
			false,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			repo := fileSystemSourceRepository{
				config: FileSystemSourceRepositoryConfig{
					ExcludedGlobs: test.excludedGlobs,
					IncludedGlobs: test.includedGlobs,
				},
			}

			ret := repo.isAcceptableSourceFile(test.path)
			assert.Equal(t, test.want, ret)
		})
	}
}
