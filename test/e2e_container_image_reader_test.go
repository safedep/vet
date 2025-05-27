package test

import (
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestContainerImageReaderEnumManifest(t *testing.T) {
	verifyE2E(t)

	testImage := "alpine:3.20"
	readerConfig := readers.DefaultContainerImageReaderConfig()

	reader, err := readers.NewContainerImageReader(testImage, readerConfig)
	assert.NoError(t, err)
	assert.NotNil(t, reader)

	err = reader.EnumManifests(func(manifest *models.PackageManifest, reader readers.PackageReader) error {
		assert.NotNil(t, manifest)
		assert.NotNil(t, reader)

		manifestID := manifest.Id()

		assert.Equal(t, manifest.Ecosystem, "Alpine:v3.20")
		assert.Equal(t, len(manifest.GetPackages()), 14)
		assert.Equal(t, manifest.GetPackages()[0].Manifest.Id(), manifestID)
		return nil
	})

	assert.NoError(t, err)
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
