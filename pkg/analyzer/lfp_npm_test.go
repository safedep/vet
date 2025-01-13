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
			[]string{},
			true,
		},
		{
			"source is a git url with user and commit-ish",
			"git+ssh://user@github.com:safedep/project.git#commit-ish",
			[]string{"git+ssh://github.com/safedep"},
			true,
		},
		{
			"source is a local relative url",
			"./a/b/c",
			[]string{},
			true,
		},
		{
			"source is a trusted url in config list of trusted urls",
			"https://registry.example.org/a/b/-/c.tgz",
			[]string{"https://registry.example.org"},
			true,
		},
		{
			"source is a trusted url when multiple trusted urls are specified",
			"https://registry.example.org/a/b/-/c.tgz",
			[]string{"https://registry.example.org", "https://registry.npmjs.org"},
			true,
		},
		{
			"source is not a trusted url when multiple trusted urls are specified but none match",
			"https://registry.example.org/a/b/-/c.tgz",
			[]string{"https://registry.npmjs.org", "git+ssh://github.com/safedep"},
			false,
		},
		{
			"source is trusted when trusted url has a base path",
			"https://registry.example.org/base/a/b/-/c.tgz",
			[]string{"https://registry.example.org/base"},
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

func TestNpmIsUrlFollowsPathConvention(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		pkgName     string
		trustedUrls []string
		expected    bool
	}{
		{
			"package name matches url path",
			"https://registry.npmjs.org/package-name/-/package-name-1.0.0.tgz",
			"package-name",
			[]string{},
			true,
		},
		{
			"package name matches scoped url path",
			"https://registry.npmjs.org/@angular/core/-/core-1.0.0.tgz",
			"@angular/core",
			[]string{},
			true,
		},
		{
			"package name does not match scoped url path",
			"https://registry.npmjs.org/@angular/core/-/core-1.0.0.tgz",
			"@someother/core",
			[]string{},
			false,
		},
		{
			"package path matches trusted url path",
			"https://registry.npmjs.org/base/package-name/-/package-name-1.0.0.tgz",
			"package-name",
			[]string{"https://registry.npmjs.org/base"},
			true,
		},
		{
			"package path matches trusted url path with trailing slash",
			"https://registry.npmjs.org/base/package-name/-/package-name-1.0.0.tgz",
			"package-name",
			[]string{"https://registry.npmjs.org/base/"},
			true,
		},
		{
			"package path matches trusted url path prefix",
			"https://registry.npmjs.org/base/package-name/-/package-name-1.0.0.tgz",
			"package-name",
			[]string{"https://registry.npmjs.org/base1/base2"},
			false,
		},
		{
			"package path has base without trusted url",
			"https://registry.npmjs.org/base/package-name/-/package-name-1.0.0.tgz",
			"package-name",
			[]string{},
			false,
		},
		{
			"package path matches one of the trusted url base",
			"https://registry.npmjs.org/base/package-name/-/package-name-1.0.0.tgz",
			"package-name",
			[]string{"https://registry.npmjs.org/base", "https://registry.npmjs.org/base1"},
			true,
		},
		{
			"package path matches the second trusted url base",
			"https://registry.npmjs.org/base1/package-name/-/package-name-1.0.0.tgz",
			"package-name",
			[]string{"https://registry.npmjs.org/base", "https://registry.npmjs.org/base1"},
			true,
		},
		{
			"strip_ansi_cjs package path matches trusted url path",
			"https://registry.npmjs.org/strip-ansi/-/strip-ansi-6.0.1.tgz",
			"strip-ansi-cjs",
			[]string{"https://registry.npmjs.org/strip-ansi"},
			true,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			actual := npmIsUrlFollowsPathConvention(test.url, test.pkgName, test.trustedUrls, test.trustedUrls)
			assert.Equal(t, test.expected, actual)
		})
	}
}
