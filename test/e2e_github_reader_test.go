package test

import (
	"os"
	"strings"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/internal/connect"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
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
			}, LockfileAs: "", SkipGitHubDependencyGraphAPI: true,
		})

		assert.Nil(t, err, "github reader builder error")

		var manifests []*models.PackageManifest
		err = githubReader.EnumManifests(func(pm *models.PackageManifest, pr readers.PackageReader) error {
			manifests = append(manifests, pm)
			return nil
		})

		assert.Nil(t, err)

		// The scanned repositories are live and their contents change over
		// time. Assert that the expected manifests are present instead of
		// asserting exact counts and positions.
		assert.GreaterOrEqual(t, len(manifests), 2)

		findManifest := func(displayPath, blobURLPrefix string) *models.PackageManifest {
			for _, pm := range manifests {
				if pm.GetDisplayPath() == displayPath &&
					strings.HasPrefix(pm.GetPath(), blobURLPrefix) {
					return pm
				}
			}
			return nil
		}

		goManifest := findManifest("go.mod",
			"https://api.github.com/repos/safedep/vet/git/blobs/")
		assert.NotNil(t, goManifest, "go.mod not found in safedep/vet")

		gradleManifest := findManifest("gradle.lockfile",
			"https://api.github.com/repos/safedep/demo-client-java/git/blobs/")
		assert.NotNil(t, gradleManifest, "gradle.lockfile not found in safedep/demo-client-java")

		if goManifest != nil {
			assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_GO, goManifest.GetControlTowerSpecEcosystem())
			assert.Greater(t, len(goManifest.Packages), 0)
		}

		if gradleManifest != nil {
			assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_MAVEN, gradleManifest.GetControlTowerSpecEcosystem())
			assert.Greater(t, len(gradleManifest.Packages), 0)
		}
	})
}
