package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNpmIsTrustedSource(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		trusted  []string
		expected bool
	}{
		{
			"source is trusted if host match is found",
			"https://registry.npmjs.org",
			[]string{"https://registry.npmjs.org"},
			true,
		},
		{
			"source is not trusted if host does not match",
			"https://registry.example.org",
			[]string{"https://registry.npmjs.com"},
			false,
		},
		{
			"source is a trusted git url matching path prefix",
			"git://github.com/safedep/vet.git",
			[]string{"git://github.com/safedep"},
			true,
		},
		{
			"source is a trusted git url but does not match path prefix",
			"git://github.com/anything/vet.git",
			[]string{"github.com/safedep"},
			false,
		},
		{
			"local urls are always trusted",
			"file:///a/b/c",
			[]string{"registry.npmjs.com"},
			true,
		},
		/*
			{
				"source is a git url with user and commit-ish",
				"git+ssh://user@github.com:safedep/project.git#commit-ish",
				[]string{"github.com/safedep"},
				true,
			},
		*/
		{
			"source is a local relative url",
			"./a/b/c",
			[]string{"https://registry.npmjs.com"},
			true,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			actual := npmIsTrustedSource(test.host, test.trusted)
			assert.Equal(t, test.expected, actual)
		})
	}
}

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
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			actual := npmNodeModulesPackagePathToName(test.path)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestNpmIsUrlFollowsPathConvention(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		pkgName  string
		expected bool
	}{
		{
			"package name matches url path",
			"https://registry.npmjs.org/package-name/-/package-name-1.0.0.tgz",
			"package-name",
			true,
		},
		{
			"package name matches scoped url path",
			"https://registry.npmjs.org/@angular/core/-/core-1.0.0.tgz",
			"@angular/core",
			true,
		},
		{
			"package name does not match scoped url path",
			"https://registry.npmjs.org/@angular/core/-/core-1.0.0.tgz",
			"@someother/core",
			false,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			actual := npmIsUrlFollowsPathConvention(test.url, test.pkgName)
			assert.Equal(t, test.expected, actual)
		})
	}
}
