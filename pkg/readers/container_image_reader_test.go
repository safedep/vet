package readers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/test"
)

func TestContainerImageReader_ApplicationName(t *testing.T) {
	cases := []struct {
		imageRef        string
		expectedAppName string
	}{
		{
			imageRef:        "alpine:latest",
			expectedAppName: "pkg:/oci/alpine:latest",
		},
		{
			imageRef:        "alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c",
			expectedAppName: "pkg:/oci/alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c",
		},
		{
			imageRef:        "./fixtures/image-tar/dummy.tar",
			expectedAppName: "file://./fixtures/image-tar/dummy.tar",
		},
	}

	for _, tc := range cases {
		t.Run(tc.imageRef, func(t *testing.T) {
			config := DefaultContainerImageReaderConfig()
			reader, err := NewContainerImageReader(tc.imageRef, config)

			assert.NoError(t, err)

			appName, err := reader.ApplicationName()
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedAppName, appName)
		})
	}
}

func TestContainerImageReader_Name(t *testing.T) {
	config := DefaultContainerImageReaderConfig()
	reader, err := NewContainerImageReader("alpine:latest", config)

	assert.NoError(t, err)
	assert.NotNil(t, reader)

	assert.Equal(t, "Container Image Reader", reader.Name())
}

// TestContainerImageReader_DpkgSourceName verifies that scanning a Debian/Ubuntu
// image populates OsvSourceName from dpkg metadata for packages where the binary
// name differs from the source package name.
func TestContainerImageReader_DpkgSourceName(t *testing.T) {
	test.EnsureEndToEndTestIsEnabled(t)

	// Binary → expected source package name mappings from issue #703.
	// These are packages where OSV requires the source name for correct lookup.
	wantSourceNames := map[string]string{
		"libgmp10":     "gmp",
		"libp11-kit0":  "p11-kit",
		"libpcre2-8-0": "pcre2",
	}

	config := DefaultContainerImageReaderConfig()
	reader, err := NewContainerImageReader("ubuntu:22.04@sha256:ce4a593b4e323dcc3dd728e397e0a866a1bf516a1b7c31d6aa06991baec4f2e0", config) // 28 MB image
	require.NoError(t, err)

	found := map[string]string{} // binary name → OsvSourceName

	err = reader.EnumManifests(func(manifest *models.PackageManifest, pr PackageReader) error {
		return pr.EnumPackages(func(pkg *models.Package) error {
			if _, interesting := wantSourceNames[pkg.GetName()]; interesting {
				found[pkg.GetName()] = pkg.OsvSourceName
			}
			return nil
		})
	})
	require.NoError(t, err)

	for binary, wantSrc := range wantSourceNames {
		t.Run(binary, func(t *testing.T) {
			got, ok := found[binary]
			assert.True(t, ok, "package %q not found in scan results", binary)
			assert.Equal(t, wantSrc, got, "OsvSourceName for binary package %q", binary)
		})
	}
}

func TestCheckPathExists(t *testing.T) {
	cases := []struct {
		name string
		path string

		isPathExists  bool
		expectedError bool
	}{
		{
			name: "valid path",
			path: "./fixtures/image-tar/dummy.tar",

			isPathExists:  true,
			expectedError: false,
		},
		{
			name: "invalid path",
			path: "./fixtures/image-tar/not-exist.tar",

			isPathExists:  false,
			expectedError: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := DefaultContainerImageReaderConfig()
			reader, err := NewContainerImageReader(tc.path, config)

			assert.NoError(t, err)
			assert.NotNil(t, reader)

			assert.Equal(t, tc.isPathExists, reader.imageTarget.isLocalFile)
		})
	}
}
