package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateArtifact(t *testing.T) {
	t.Run("accepts an artifact with all required fields", func(t *testing.T) {
		artifact := GoreleaserArtifact{
			Path:   "dist/vet_linux_amd64/vet",
			Goos:   "linux",
			Goarch: "amd64",
			Type:   "Binary",
		}

		require.NoError(t, validateArtifact(artifact))
	})

	for _, field := range []string{"path", "goos", "type"} {
		field := field
		t.Run("rejects a missing "+field, func(t *testing.T) {
			artifact := GoreleaserArtifact{
				Path: "dist/vet_linux_amd64/vet",
				Goos: "linux",
				Type: "Binary",
			}

			switch field {
			case "path":
				artifact.Path = ""
			case "goos":
				artifact.Goos = ""
			case "type":
				artifact.Type = ""
			}

			err := validateArtifact(artifact)
			require.Error(t, err)
			assert.Contains(t, err.Error(), field)
		})
	}
}
