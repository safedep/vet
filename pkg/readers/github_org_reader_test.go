package readers

import (
	"errors"
	"testing"

	"github.com/google/go-github/v70/github"
	"github.com/safedep/dry/utils"
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

func TestGithubIsExcludedRepo(t *testing.T) {
	cases := []struct {
		name           string
		repo           *github.Repository
		config         *GithubOrgReaderConfig
		expectedExcl   bool
		expectedReason string
	}{
		{
			name: "no exclusion - default config",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/repo1"),
				Archived: utils.PtrTo(false),
				Fork:     utils.PtrTo(false),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{},
				IncludeArchived: true,
				IncludeForks:    true,
				PrivateOnly:     false,
			},
			expectedExcl:   false,
			expectedReason: "",
		},
		{
			name: "explicitly excluded - exact match",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/repo1"),
				Archived: utils.PtrTo(false),
				Fork:     utils.PtrTo(false),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{"org/repo1"},
				IncludeArchived: true,
				IncludeForks:    true,
				PrivateOnly:     false,
			},
			expectedExcl:   true,
			expectedReason: "explicitly excluded",
		},
		{
			name: "explicitly excluded - with whitespace",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/repo1"),
				Archived: utils.PtrTo(false),
				Fork:     utils.PtrTo(false),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{"  org/repo1  ", "org/other"},
				IncludeArchived: true,
				IncludeForks:    true,
				PrivateOnly:     false,
			},
			expectedExcl:   true,
			expectedReason: "explicitly excluded",
		},
		{
			name: "not in exclusion list",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/repo1"),
				Archived: utils.PtrTo(false),
				Fork:     utils.PtrTo(false),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{"org/repo2", "org/repo3"},
				IncludeArchived: true,
				IncludeForks:    true,
				PrivateOnly:     false,
			},
			expectedExcl:   false,
			expectedReason: "",
		},
		{
			name: "archived repo excluded when IncludeArchived is false",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/archived-repo"),
				Archived: utils.PtrTo(true),
				Fork:     utils.PtrTo(false),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{},
				IncludeArchived: false,
				IncludeForks:    true,
				PrivateOnly:     false,
			},
			expectedExcl:   true,
			expectedReason: "archived",
		},
		{
			name: "archived repo included when IncludeArchived is true",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/archived-repo"),
				Archived: utils.PtrTo(true),
				Fork:     utils.PtrTo(false),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{},
				IncludeArchived: true,
				IncludeForks:    true,
				PrivateOnly:     false,
			},
			expectedExcl:   false,
			expectedReason: "",
		},
		{
			name: "forked repo excluded when IncludeForks is false",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/forked-repo"),
				Archived: utils.PtrTo(false),
				Fork:     utils.PtrTo(true),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{},
				IncludeArchived: true,
				IncludeForks:    false,
				PrivateOnly:     false,
			},
			expectedExcl:   true,
			expectedReason: "forked",
		},
		{
			name: "forked repo included when IncludeForks is true",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/forked-repo"),
				Archived: utils.PtrTo(false),
				Fork:     utils.PtrTo(true),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{},
				IncludeArchived: true,
				IncludeForks:    true,
				PrivateOnly:     false,
			},
			expectedExcl:   false,
			expectedReason: "",
		},
		{
			name: "public repo excluded when PrivateOnly is true",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/public-repo"),
				Archived: utils.PtrTo(false),
				Fork:     utils.PtrTo(false),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{},
				IncludeArchived: true,
				IncludeForks:    true,
				PrivateOnly:     true,
			},
			expectedExcl:   true,
			expectedReason: "not private",
		},
		{
			name: "private repo included when PrivateOnly is true",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/private-repo"),
				Archived: utils.PtrTo(false),
				Fork:     utils.PtrTo(false),
				Private:  utils.PtrTo(true),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{},
				IncludeArchived: true,
				IncludeForks:    true,
				PrivateOnly:     true,
			},
			expectedExcl:   false,
			expectedReason: "",
		},
		{
			name: "public repo included when PrivateOnly is false",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/public-repo"),
				Archived: utils.PtrTo(false),
				Fork:     utils.PtrTo(false),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{},
				IncludeArchived: true,
				IncludeForks:    true,
				PrivateOnly:     false,
			},
			expectedExcl:   false,
			expectedReason: "",
		},
		{
			name: "multiple exclusion criteria - archived and forked",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/archived-fork"),
				Archived: utils.PtrTo(true),
				Fork:     utils.PtrTo(true),
				Private:  utils.PtrTo(false),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{},
				IncludeArchived: false,
				IncludeForks:    false,
				PrivateOnly:     false,
			},
			expectedExcl:   true,
			expectedReason: "archived", // First check that matches
		},
		{
			name: "explicit exclusion takes precedence",
			repo: &github.Repository{
				FullName: utils.PtrTo("org/excluded-repo"),
				Archived: utils.PtrTo(false),
				Fork:     utils.PtrTo(false),
				Private:  utils.PtrTo(true),
			},
			config: &GithubOrgReaderConfig{
				ExcludeRepos:    []string{"org/excluded-repo"},
				IncludeArchived: true,
				IncludeForks:    true,
				PrivateOnly:     false,
			},
			expectedExcl:   true,
			expectedReason: "explicitly excluded",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			excluded, reason := githubIsExcludedRepo(tc.repo, tc.config)
			assert.Equal(t, tc.expectedExcl, excluded, "Expected exclusion status mismatch")
			assert.Equal(t, tc.expectedReason, reason, "Expected exclusion reason mismatch")
		})
	}
}
