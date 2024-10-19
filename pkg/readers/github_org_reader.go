package readers

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/google/go-github/v54/github"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

const (
	githubOrgReaderPerPageSize = 100
)

type GithubOrgReaderConfig struct {
	OrganizationURL        string
	IncludeArchived        bool
	MaxRepositories        int
	SkipDependencyGraphAPI bool
}

type githubOrgReader struct {
	client             *github.Client
	config             *GithubOrgReaderConfig
	scannedRepoCounter int
}

// NewGithubOrgReader creates a [PackageManifestReader] which enumerates
// a Github org, identifying repositories and scanning them using [githubReader]
func NewGithubOrgReader(client *github.Client,
	config *GithubOrgReaderConfig) (PackageManifestReader, error) {
	return &githubOrgReader{
		client:             client,
		config:             config,
		scannedRepoCounter: 0,
	}, nil
}

func (p *githubOrgReader) Name() string {
	return "Github Organization Package Manifest Reader"
}

func (p *githubOrgReader) EnumManifests(handler func(*models.PackageManifest,
	PackageReader) error) error {
	ctx := context.Background()

	gitOrg, err := githubOrgFromURL(p.config.OrganizationURL)
	if err != nil {
		return err
	}

	listOptions := &github.ListOptions{
		Page:    0,
		PerPage: githubOrgReaderPerPageSize,
	}

	for {
		if err := ctx.Err(); err != nil {
			logger.Errorf("Context error: %v", err)
			break
		}

		if p.isRepoLimitReached() {
			logger.Infof("Stopping repository enumeration due to max %d limit reached",
				p.config.MaxRepositories)
			break
		}

		repositories, resp, err := p.client.Repositories.ListByOrg(ctx, gitOrg,
			&github.RepositoryListByOrgOptions{
				ListOptions: *listOptions,
			})

		if err != nil {
			logger.Errorf("Failed to list Github org: %v", err)
			break
		}

		logger.Infof("Enumerated %d repositories with page: %d and next page: %d",
			len(repositories), listOptions.Page, resp.NextPage)

		err = p.handleRepositoryBatch(repositories, handler)
		if err != nil {
			logger.Errorf("Failed to handle repository batch: %v", err)
			break
		}

		if resp.NextPage == 0 {
			break
		}

		listOptions.Page = resp.NextPage
	}

	return nil
}

func (p *githubOrgReader) isRepoLimitReached() bool {
	return (p.config.MaxRepositories != 0) &&
		(p.scannedRepoCounter >= p.config.MaxRepositories)
}

// withIncrementedRepoCount executes fn while incrementing the repository
// count. It returns a boolean indicating if repo count is reached
func (p *githubOrgReader) withIncrementedRepoCount(fn func()) bool {
	fn()
	p.scannedRepoCounter = p.scannedRepoCounter + 1

	return p.isRepoLimitReached()
}

func (p *githubOrgReader) handleRepositoryBatch(repositories []*github.Repository,
	handler PackageManifestHandlerFn) error {

	var repoUrls []string
	for _, repo := range repositories {
		breach := p.withIncrementedRepoCount(func() {
			repoUrls = append(repoUrls, repo.GetCloneURL())
		})

		if breach {
			break
		}
	}

	if len(repoUrls) == 0 {
		return nil
	}

	githubReader, err := NewGithubReader(p.client, GitHubReaderConfig{
		Urls:                         repoUrls,
		SkipGitHubDependencyGraphAPI: p.config.SkipDependencyGraphAPI,
	})

	if err != nil {
		return err
	}

	return githubReader.EnumManifests(handler)
}

// Making this exposed so that we can test this independently
func githubOrgFromURL(githubUrl string) (string, error) {
	u, err := url.Parse(githubUrl)
	if err != nil {
		return "", err
	}

	// Handling special case which is acceptable to url.Parse
	if u.Scheme == "" {
		return "", errors.New("rejecting URL without a scheme")
	}

	parts := strings.Split(u.Path, "/")
	if len(parts) < 2 || parts[1] == "" {
		return "", errors.New("rejecting URL without an org")
	}

	return parts[1], nil
}
