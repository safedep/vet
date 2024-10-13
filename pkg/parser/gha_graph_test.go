package parser

import (
	"testing"

	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestParseGithubActionWorkflowAsGraph(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		countOfPkgs int
		err         error
	}{
		{
			name:        "Empty YAML",
			path:        "./fixtures/gha/.github/workflows/empty.yml",
			countOfPkgs: 0,
		},
		{
			name:        "vet CI Workflow Example",
			path:        "./fixtures/gha/.github/workflows/ci.yml",
			countOfPkgs: 4,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			m, err := parseGithubActionWorkflowAsGraph(test.path, nil)
			if test.err != nil {
				assert.Error(t, err)
				assert.ErrorContains(t, err, test.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.countOfPkgs, len(m.Packages))
				assert.Equal(t, models.EcosystemGitHubActions, m.Ecosystem)
			}
		})
	}
}
