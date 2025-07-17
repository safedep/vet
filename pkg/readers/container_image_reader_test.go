package readers

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
