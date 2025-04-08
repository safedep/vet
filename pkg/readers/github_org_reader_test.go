package readers

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGithubOrgReader(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		org     string
		appName string
		err     error
	}{
		{
			"URL is invalid",
			"aaaa",
			"",
			"",
			errors.New("rejecting URL without a scheme"),
		},
		{
			"URL does not have org",
			"https://github.com/",
			"",
			"",
			errors.New("rejecting URL without an org"),
		},
		{
			"URL does not have org slash",
			"https://github.com",
			"",
			"",
			errors.New("rejecting URL without an org"),
		},

		{
			"URL has org",
			"https://github.com/org1",
			"org1",
			"vet-scanned-org1-projects",
			nil,
		},
		{
			"URL has org++",
			"https://github.com/org1/repo.git?x=1",
			"org1",
			"vet-scanned-org1-projects",
			nil,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			org, err := githubOrgFromURL(test.url)

			if test.err != nil {
				assert.ErrorContains(t, err, test.err.Error())
			} else {
				assert.Equal(t, test.org, org)
			}

			ghReader := &githubOrgReader{
				config: &GithubOrgReaderConfig{
					OrganizationURL: test.url,
				},
			}
			appName, err := ghReader.ApplicationName()
			if test.err != nil {
				assert.ErrorContains(t, err, test.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.appName, appName)
			}
		})
	}
}
