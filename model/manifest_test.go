package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestManifestKindOrigin(t *testing.T) {
	cases := map[ManifestKind]Packages{
		ManifestKindLockfile:  PackagesDeclared,
		ManifestKindManifest:  PackagesDeclared,
		ManifestKindSBOM:      PackagesDeclared,
		ManifestKindWorkflow:  PackagesDeclared,
		ManifestKindInstalled: PackagesInstalled,
		ManifestKindEndpoint:  PackagesInstalled,
	}
	for kind, want := range cases {
		assert.Equal(t, want, kind.Origin(), kind)
	}
}
