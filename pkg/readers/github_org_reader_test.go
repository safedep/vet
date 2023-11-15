package readers

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOrgFromURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		org  string
		err  error
	}{
		{
			"URL is invalid",
			"aaaa",
			"",
			errors.New("rejecting URL without a scheme"),
		},
		{
			"URL does not have org",
			"https://github.com/",
			"",
			errors.New("rejecting URL without an org"),
		},
		{
			"URL does not have org slash",
			"https://github.com",
			"",
			errors.New("rejecting URL without an org"),
		},

		{
			"URL has org",
			"https://github.com/org1",
			"org1",
			nil,
		},
		{
			"URL has org++",
			"https://github.com/org1/repo.git?x=1",
			"org1",
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
		})
	}
}
