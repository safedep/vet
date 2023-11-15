package test

import (
	"os"
	"testing"

	"github.com/safedep/vet/internal/connect"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
	"github.com/stretchr/testify/assert"
)

func TestGithubOrgReaderWithSafeDepOrg(t *testing.T) {
	verifyE2E(t)

	t.Run("Test Reader using SafeDep Github Org without auth", func(t *testing.T) {
		githubToken := os.Getenv("GITHUB_TOKEN")

		t.Cleanup(func() {
			os.Setenv("GITHUB_TOKEN", githubToken)
		})

		os.Setenv("GITHUB_TOKEN", "")
		githubClient, err := connect.GetGithubClient()
		assert.Nil(t, err)

		githubOrgReader, err := readers.NewGithubOrgReader(githubClient, &readers.GithubOrgReaderConfig{
			OrganizationURL: "https://github.com/safedep",
			MaxRepositories: 5,
		})

		assert.Nil(t, err)

		var manifests []*models.PackageManifest
		err = githubOrgReader.EnumManifests(func(pm *models.PackageManifest, pr readers.PackageReader) error {
			manifests = append(manifests, pm)
			return nil
		})

		assert.Nil(t, err)
		assert.Greater(t, len(manifests), 0)
	})
}
