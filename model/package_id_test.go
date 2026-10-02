package model

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPURLMatchesTheEncoder(t *testing.T) {
	ids := []PackageID{
		{Ecosystem: EcosystemNpm, Name: "left-pad", Version: "1.3.0"},
		{Ecosystem: EcosystemNpm, Namespace: "@types", Name: "node", Version: "20.1.0"},
		{Ecosystem: EcosystemNpm, Name: "a/b", Version: "1.0.0"},
		{Ecosystem: EcosystemNpm, Name: "x", Version: "1.0.0+build/1"},
		{Ecosystem: EcosystemNpm, Name: "x", Version: "file:../x"},
		{Ecosystem: EcosystemNpm, Name: "x y", Version: "1"},
		{Ecosystem: EcosystemNpm, Name: "no-version"},
		{Ecosystem: EcosystemMaven, Namespace: "org.apache.commons", Name: "commons-lang3", Version: "3.14.0"},
		{Ecosystem: EcosystemGo, Namespace: "github.com/stretchr", Name: "testify", Version: "v1.9.0"},
		{Ecosystem: EcosystemGo, Namespace: "/github.com//a/", Name: "b", Version: "v0.0.0-2024"},
		{Ecosystem: EcosystemGitHubActions, Namespace: "github", Name: "codeql-action", Version: "v3", Subpath: "init"},
		{Ecosystem: EcosystemGitHubActions, Namespace: "o", Name: "r", Version: "v1", Subpath: "/a//b/"},
		{Ecosystem: EcosystemPyPI, Name: "requests", Version: "2.32.0~rc1"},
		{Ecosystem: EcosystemPyPI, Name: "torch", Version: "2.0.0+cu118"},
	}
	for _, id := range ids {
		t.Run(id.Name+"@"+id.Version, func(t *testing.T) {
			info, err := id.Ecosystem.Info()
			require.NoError(t, err)
			want := packageurl.NewPackageURL(info.PURLType, id.Namespace, id.Name, id.Version, nil, id.Subpath).ToString()
			assert.Equal(t, want, id.PURL())
		})
	}
}

func TestNewPackageIDMatchesParsePURL(t *testing.T) {
	cases := []struct{ typ, ns, name, version, subpath string }{
		{"npm", "", "left-pad", "1.3.0", ""},
		{"npm", "@Types", "Node", "20.1.0", ""},
		{"pypi", "", "Flask_Login", "0.6.3", ""},
		{"golang", "github.com/stretchr", "testify", "v1.9.0", ""},
		{"golang", "", "github.com/stretchr/testify", "v1.9.0", ""},
		{"maven", "org.apache.commons", "commons-lang3", "3.14.0", ""},
		{"github", "github", "codeql-action", "v3", "init"},
		{"cargo", "", "serde", "1.0.200", ""},
	}
	for _, tc := range cases {
		t.Run(tc.typ+"/"+tc.name, func(t *testing.T) {
			s := packageurl.NewPackageURL(tc.typ, tc.ns, tc.name, tc.version, nil, tc.subpath).ToString()
			want, wantErr := ParsePURL(s)
			got, err := NewPackageID(tc.typ, tc.ns, tc.name, tc.version, tc.subpath)
			assert.Equal(t, wantErr, err)
			assert.Equal(t, want, got)
		})
	}
	_, err := NewPackageID("nope", "", "x", "1", "")
	assert.Error(t, err)
}
