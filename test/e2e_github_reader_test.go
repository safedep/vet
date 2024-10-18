package test

import (
	"os"
	"strings"
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
			"https://github.com/safedep/demo-client-java",
		}, "")

		assert.Nil(t, err, "github reader builder error")

		var manifests []*models.PackageManifest
		err = githubReader.EnumManifests(func(pm *models.PackageManifest, pr readers.PackageReader) error {
			manifests = append(manifests, pm)
			return nil
		})

		assert.Nil(t, err)

		assert.Equal(t, len(manifests), 2)

		assert.NotNil(t, manifests[0])
		assert.NotNil(t, manifests[1])

		assert.Equal(t, manifests[0].GetSpecEcosystem().String(), modelspec.Ecosystem_SpdxSBOM.String())
		assert.Equal(t, "https://github.com/safedep/vet.git", manifests[0].GetDisplayPath(), "found in Dependency API (SBOM)")
		assert.Equal(t, "", manifests[0].GetPath())
		assert.Greater(t, len(manifests[0].Packages), 0)

		assert.True(t, strings.HasPrefix(manifests[1].GetDisplayPath(),
			"https://api.github.com/repos/safedep/demo-client-java/git/blobs/"),
			"found by enumerating top level directory")

		assert.Greater(t, len(manifests[1].Packages), 0)
	})
}
