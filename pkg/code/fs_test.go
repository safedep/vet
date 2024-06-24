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

func TestGetRelativePath(t *testing.T) {
	cases := []struct {
		name           string
		path           string
		sourcePaths    []string
		importPaths    []string
		includeImports bool
		want           string
		err            bool
	}{
		{
			"Relative in source path with no imports",
			"/a/b/c/foo.go",
			[]string{"/a/b"},
			[]string{},
			false,
			"c/foo.go",
			false,
		},
		{
			"Relative in source path with imports",
			"/a/b/c/foo.go",
			[]string{"/a/b"},
			[]string{"/a/b/c"},
			true,
			"c/foo.go",
			false,
		},
		{
			"Relative in import path with imports",
			"/a/b/c/foo.go",
			[]string{"/x/y"},
			[]string{"/a/b"},
			true,
			"c/foo.go",
			false,
		},
		{
			"First match in import path",
			"/a/b/c/foo.go",
			[]string{"/x/y"},
			[]string{"/a/b", "/a/b/c"},
			true,
			"c/foo.go",
			false,
		},
		{
			"Relative in source path",
			"./a/b/c/foo.go",
			[]string{"./a/b"},
			[]string{"/a/b/c"},
			true,
			"c/foo.go",
			false,
		},
		{
			"No match",
			"/a/b/c/foo.go",
			[]string{"/x/y"},
			[]string{"/z"},
			true,
			"",
			true,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			repo := fileSystemSourceRepository{
				config: FileSystemSourceRepositoryConfig{
					SourcePaths: test.sourcePaths,
					ImportPaths: test.importPaths,
				},
			}

			ret, err := repo.GetRelativePath(test.path, test.includeImports)
			if test.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.want, ret)
			}
		})
	}
}
