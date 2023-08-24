package connect

import (
	"context"
	"os"
	"strings"

	"github.com/gofri/go-github-ratelimit/github_ratelimit"
	"github.com/google/go-github/v54/github"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/common/logger"
	"golang.org/x/oauth2"
)

const (
	// We are storing the Github oauth2 client ID here. While this may not be
	// the best way to store client id, this does not introduce any risk because
	// it cannot be used for any authentication by itself
	githubOAuth2ClientId       = "9b535a30e967c5d4e2ca"
	githubOAuth2ClientIdEnvKey = "VET_GITHUB_CLIENT_ID"
)

func PersistGithubAccessToken(token string) error {
	return updateConfig(func(c *Config) {
		c.GithubAccessToken = token
	})
}

func GetGithubOAuth2ClientId() string {
	clientID := strings.ToLower(os.Getenv(githubOAuth2ClientIdEnvKey))
	if !utils.IsEmptyString(clientID) {
		return clientID
	}

	return githubOAuth2ClientId
}

func GetGithubClient() (*github.Client, error) {
	github_token := os.Getenv("GITHUB_TOKEN")
	if !utils.IsEmptyString(github_token) {
		logger.Debugf("Found GITHUB_TOKEN env variable, using it to access Github.")
	} else {
		github_token = globalConfig.GithubAccessToken
	}

	if utils.IsEmptyString(github_token) {
		logger.Debugf("Creating a Github client without credential")
		return github.NewClient(nil), nil
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: github_token,
	})

	baseClient := oauth2.NewClient(context.Background(), tokenSource)
	rateLimitedClient, err := github_ratelimit.NewRateLimitWaiterClient(baseClient.Transport)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Created a new Github client with rate limit waiter")
	return github.NewClient(rateLimitedClient), nil
}
