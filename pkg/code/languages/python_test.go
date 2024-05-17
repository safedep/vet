package languages

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveImportNameFromPath(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		expected string
		err      error
	}{
		{
			name:     "Path is module",
			path:     "module.py",
			expected: "module",
			err:      nil,
		},
		{
			name:     "Path is module with subdirectory",
			path:     "subdir/module.py",
			expected: "subdir.module",
			err:      nil,
		},
		{
			name:     "Path is module with subdirectory and init",
			path:     "subdir/__init__.py",
			expected: "subdir",
			err:      nil,
		},
		{
			name:     "Absolute path",
			path:     "/subdir/module.py",
			expected: "",
			err:      fmt.Errorf("path is not relative: /subdir/module.py"),
		},
	}

	l := &pythonSourceLanguage{}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			res, err := l.ResolveImportNameFromPath(test.path)

			if test.err != nil {
				assert.ErrorContains(t, err, test.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, res)
			}
		})
	}
}
