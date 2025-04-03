package readers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
