package parser

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListParser(t *testing.T) {
	parsers := List(false)
	assert.Equal(t, 19, len(parsers))
}

func TestInvalidEcosystemMapping(t *testing.T) {
	pw := &parserWrapper{parseAs: "nothing"}
	assert.Empty(t, pw.Ecosystem())
}

func TestEcosystemMapping(t *testing.T) {
	for _, lf := range List(false) {
		t.Run(lf, func(t *testing.T) {
			// For graph parsers, we add a tag to the end of the name
			lf = strings.Split(lf, " ")[0]

			pw := &parserWrapper{parseAs: lf}
			assert.NotEmpty(t, pw.Ecosystem())
		})
	}
}

func TestFindParserForGitHubAction(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		pathAs string
		err    error
	}{
		{
			name: "Valid GHA workflow file",
			path: "/a/.github/workflows/ci.yml",
		},
		{
			name: "Valid GHA action file",
			path: "/a/.github/actions/ci.yml",
		},
		{
			name: "Invalid GHA file",
			path: "/a/b/c.yml",
			err:  errors.New("no parser found with:"),
		},
		{
			name:   "Invalid GHA file path but explicitly provided as GHA file",
			path:   "/a/b/c.yml",
			pathAs: "github-actions",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			pw, err := FindParser(test.path, test.pathAs)
			if test.err != nil {
				assert.Error(t, err)
				assert.ErrorContains(t, err, test.err.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pw)
				assert.Equal(t, "GitHubActions", pw.Ecosystem())
			}
		})
	}
}
