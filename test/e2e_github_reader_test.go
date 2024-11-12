package test

import (
	"os"
	"strings"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/vet/internal/connect"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
	"github.com/stretchr/testify/assert"
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

		githubReader, err := readers.NewGithubReader(githubClient, readers.GitHubReaderConfig{
			Urls: []string{
				"https://github.com/safedep/vet",
				"https://github.com/safedep/demo-client-java",
			}, LockfileAs: "", SkipGitHubDependencyGraphAPI: true})

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

		assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_GO, manifests[0].GetControlTowerSpecEcosystem())
		assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_MAVEN, manifests[1].GetControlTowerSpecEcosystem())

		assert.Equal(t, "go.mod", manifests[0].GetDisplayPath(), "found in GitHub repository")
		assert.True(t, strings.HasPrefix(manifests[0].GetPath(),
			"https://api.github.com/repos/safedep/vet/git/blobs/"))

		assert.Equal(t, "gradle.lockfile", manifests[1].GetDisplayPath(), "found in GitHub repository")
		assert.True(t, strings.HasPrefix(manifests[1].GetPath(),
			"https://api.github.com/repos/safedep/demo-client-java/git/blobs/"))

		assert.Greater(t, len(manifests[0].Packages), 0)
		assert.Greater(t, len(manifests[1].Packages), 0)
	})
}
