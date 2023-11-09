package test

import (
	"os"
	"testing"

	"github.com/safedep/vet/internal/connect"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
	"github.com/stretchr/testify/assert"

	modelspec "github.com/safedep/vet/gen/models"
)

func TestGithubReaderWithVetPublicRepository(t *testing.T) {
	verifyE2E(t)

	t.Run("Test Reader on vet Public Repository", func(t *testing.T) {
		githubToken := os.Getenv("GITHUB_TOKEN")

		t.Cleanup(func() {
			os.Setenv("GITHUB_TOKEN", githubToken)
		})

		os.Setenv("GITHUB_TOKEN", "")
		githubClient, err := connect.GetGithubClient()

		assert.Nil(t, err, "github client creation error")

		githubReader, err := readers.NewGithubReader(githubClient, []string{
			"https://github.com/safedep/vet",
		}, "")

		assert.Nil(t, err, "github reader builder error")

		var manifest *models.PackageManifest
		err = githubReader.EnumManifests(func(pm *models.PackageManifest, pr readers.PackageReader) error {
			manifest = pm
			return nil
		})

		assert.Nil(t, err)
		assert.NotNil(t, manifest)

		assert.Equal(t, manifest.GetSpecEcosystem().String(), modelspec.Ecosystem_SpdxSBOM.String())
		assert.Equal(t, "https://github.com/safedep/vet.git", manifest.GetDisplayPath())

		assert.Greater(t, len(manifest.Packages), 0)
	})
}
