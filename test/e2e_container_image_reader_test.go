package test

import (
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestContainerImageReaderEnumManifest(t *testing.T) {
	verifyE2E(t)

	cases := []struct {
		name              string
		imageRef          string
		expectedErr       bool
		expectedEcosystem string
		expectedPackages  int
	}{
		{
			name:              "valid image with version",
			imageRef:          "alpine:3.20",
			expectedErr:       false,
			expectedPackages:  14,
			expectedEcosystem: "Alpine:v3.20",
		},
		{
			name:              "valid image with sha",
			imageRef:          "alpine:3.20@sha256:de4fe7064d8f98419ea6b49190df1abbf43450c1702eeb864fe9ced453c1cc5f",
			expectedErr:       false,
			expectedPackages:  14,
			expectedEcosystem: "Alpine:v3.20",
		},
		{
			name:        "invalid image with version",
			imageRef:    "alpine:9999.999.939489", // Random Unavailable Version
			expectedErr: true,
		},
		{
			name:        "invalid image",
			imageRef:    "some-random-image-that-does-not-exists",
			expectedErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			readerConfig := readers.DefaultContainerImageReaderConfig()
			reader, err := readers.NewContainerImageReader(tc.imageRef, readerConfig)

			if tc.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, reader)

				err = reader.EnumManifests(func(manifest *models.PackageManifest, reader readers.PackageReader) error {
					assert.NotNil(t, manifest)
					assert.NotNil(t, reader)

					manifestID := manifest.Id()

					assert.Equal(t, manifest.Ecosystem, tc.expectedEcosystem)
					assert.Equal(t, len(manifest.GetPackages()), tc.expectedPackages)
					assert.Equal(t, manifest.GetPackages()[0].Manifest.Id(), manifestID)
					return nil
				})

				assert.NoError(t, err)
			}
		})
	}

}

func TestContainerImageReaderApplicationName(t *testing.T) {
	verifyE2E(t)

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
	}

	for _, tc := range cases {
		t.Run(tc.imageRef, func(t *testing.T) {
			config := readers.DefaultContainerImageReaderConfig()
			reader, err := readers.NewContainerImageReader(tc.imageRef, config)

			assert.NoError(t, err)

			appName, err := reader.ApplicationName()
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedAppName, appName)
		})
	}
}
