package readers

import (
	"context"
	"testing"

	"github.com/google/go-github/v70/github"
	"github.com/stretchr/testify/assert"
)

func TestGithubReaderFetchRemoteFileToLocalFile(t *testing.T) {
	client := github.NewClient(nil)

	t.Run("should fetch a file from github", func(t *testing.T) {
		reader, err := NewGithubReader(nil, GitHubReaderConfig{
			Urls: []string{"https://github.com/safedep/vet"},
		})
		assert.NoError(t, err)

		tempFile, err := reader.fetchRemoteFileToLocalFile(context.Background(), client, "safedep", "vet", "README.md", "main")

		assert.NoError(t, err)
		assert.FileExists(t, tempFile)
	})

	t.Run("should not crash while fetching a directory", func(t *testing.T) {
		reader, err := NewGithubReader(nil, GitHubReaderConfig{
			Urls: []string{"https://github.com/safedep/vet"},
		})
		assert.NoError(t, err)

		tempFile, err := reader.fetchRemoteFileToLocalFile(context.Background(), client, "safedep", "vet", "docs", "main")
		assert.Error(t, err)
		assert.Empty(t, tempFile)
	})
}

func TestGithubReaderApplicationName(t *testing.T) {
	cases := []struct {
		name    string
		urls    []string
		appName string
	}{
		{
			name:    "no urls",
			urls:    []string{},
			appName: "vet-scanned-github-projects",
		},
		{
			name:    "single url",
			urls:    []string{"https://github.com/safedep/code"},
			appName: "code",
		},
		{
			name:    "single url",
			urls:    []string{"https://github.com/safedep/code.git"},
			appName: "code",
		},
		{
			name:    "multiple urls",
			urls:    []string{"https://github.com/safedep/code", "https://github.com/safedep/vet"},
			appName: "vet-scanned-github-projects",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			reader, err := NewGithubReader(nil, GitHubReaderConfig{
				Urls: testCase.urls,
			})
			assert.NoError(t, err)

			appName, err := reader.ApplicationName()
			assert.NoError(t, err)

			assert.Equal(t, testCase.appName, appName)
		})
	}
}
