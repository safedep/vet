package readers

import (
	"github.com/stretchr/testify/assert"
	"testing"
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

func TestContainerImageReader_LocalImageNotSupported(t *testing.T) {
	config := &ContainerImageReaderConfig{
		// This is not supported, hence it will give error
		RemoteImageFetch: false,
	}

	reader, err := NewContainerImageReader("alpine:latest", config)

	assert.Error(t, err)
	assert.Nil(t, reader)
}

func TestContainerImageReader_Name(t *testing.T) {
	config := DefaultContainerImageReaderConfig()
	reader, err := NewContainerImageReader("alpine:latest", config)

	assert.NoError(t, err)
	assert.NotNil(t, reader)

	assert.Equal(t, "Container Image Reader", reader.Name())
}
