package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNpmNodeModulesPackagePathToName(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		expected string
	}{
		{
			"package name is extracted from path",
			"/a/b/c/node_modules/package-name",
			"package-name",
		},
		{
			"node_modules relative",
			"node_modules/express",
			"express",
		},
		{
			"node_modules relative scoped name",
			"node_modules/@angular/core",
			"@angular/core",
		},
		{
			"nested node_modules relative",
			"node_modules/@angular/core/node_modules/express",
			"express",
		},
		{
			"nested node_modules relative scoped name",
			"node_modules/@angular/core/node_modules/@angular/common",
			"@angular/common",
		},
		{
			"prefixed without node_modules",
			"prefix/node_modules/express",
			"express",
		},
		{
			"node_modules is not mandatory",
			"libs/@angular/core",
			"@angular/core",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			actual := NpmNodeModulesPackagePathToName(test.path)
			assert.Equal(t, test.expected, actual)
		})
	}
}
