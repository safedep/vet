package connect

import (
	"context"
	"net/http"
	"os"
	"strconv"
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
	githubToken := os.Getenv("GITHUB_TOKEN")
	if !utils.IsEmptyString(githubToken) {
		logger.Debugf("Found GITHUB_TOKEN env variable, using it to access Github.")
	} else {
		githubToken = globalConfig.GithubAccessToken
	}

	if utils.IsEmptyString(githubToken) {
		rateLimitedClient, err := githubRateLimitedClient(http.DefaultTransport)
		if err != nil {
			return nil, err
		}

		logger.Debugf("Creating a Github client without credential")
		return github.NewClient(rateLimitedClient), nil
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: githubToken,
	})

	baseClient := oauth2.NewClient(context.Background(), tokenSource)
	rateLimitedClient, err := githubRateLimitedClient(baseClient.Transport)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Created a new Github client with credential")
	return github.NewClient(rateLimitedClient), nil
}

// This is currently effective only for Github secondary rate limits
// https://docs.github.com/en/rest/overview/rate-limits-for-the-rest-api
func githubRateLimitedClient(transport http.RoundTripper) (*http.Client, error) {
	var options []github_ratelimit.Option

	if !githubClientRateLimitBlockDisabled() {
		logger.Debugf("Adding Github rate limit callbacks to client")

		options = append(options, github_ratelimit.WithLimitDetectedCallback(func(cc *github_ratelimit.CallbackContext) {
			logger.Infof("Github rate limit detected, sleep until: %s", cc.SleepUntil)
		}))
	}

	rateLimitedClient, err := github_ratelimit.NewRateLimitWaiterClient(transport, options...)
	if err != nil {
		return nil, err
	}

	return rateLimitedClient, err
}

// We implement this as an internal feature i.e. without a config or an UI option because
// we want this to be the default behaviour *always* unless user want to explicitly disable it
func githubClientRateLimitBlockDisabled() bool {
	ret, err := strconv.ParseBool(os.Getenv("VET_GITHUB_DISABLE_RATE_LIMIT_BLOCKING"))
	if err != nil {
		return false
	}

	return ret
}
