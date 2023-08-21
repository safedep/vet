package connect

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/gofri/go-github-ratelimit/github_ratelimit"
	"github.com/google/go-github/v54/github"
	"github.com/safedep/vet/pkg/common/logger"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

// with go modules enabled (GO111MODULE=on or outside GOPATH)
// with go modules disabled

const (
	homeRelativeConfigPath = ".safedep/connected-apps.yml"
)

var githubClient *github.Client

type Config struct {
	GithubAccessToken string `yaml:"github_access_token"`
}

// Connected Apps Global config to be used during runtime
var globalConfig *Config

func init() {
	err := loadConfiguration()
	logger.Debugf("Error while loading connected apps configuration %v", err)
}

func Configure(m Config) error {
	globalConfig = &m
	return persistConfiguration()
}

func GetConfigFile() string {
	return homeRelativeConfigPath
}

func GetGithubClient() (*github.Client, error) {
	if githubClient == nil {
		ctx := context.Background()
		github_token, err := getGithubAccessToken()
		if err != nil {
			// Create Client with no access token, it may be useful to access public repos
			tc := oauth2.NewClient(ctx, nil)
			rateLimiter, err := github_ratelimit.NewRateLimitWaiterClient(tc.Transport)
			if err != nil {
				return nil, err
			}
			githubClient = github.NewClient(rateLimiter)

		} else {
			// Create Client with the access token
			ts := oauth2.StaticTokenSource(
				&oauth2.Token{AccessToken: github_token},
			)
			tc := oauth2.NewClient(ctx, ts)
			rateLimiter, err := github_ratelimit.NewRateLimitWaiterClient(tc.Transport)
			if err != nil {
				return nil, err
			}
			githubClient = github.NewClient(rateLimiter)
		}
	}
	return githubClient, nil
}

// Get Github Access token using various techniques
func getGithubAccessToken() (string, error) {
	github_token := os.Getenv("GITHUB_TOKEN")
	if github_token != "" {
		logger.Debugf("Found GITHUB_TOKEN env variable, using it to access Gtihub.")
	}

	github_token = globalConfig.GithubAccessToken
	if github_token != "" {
		logger.Debugf("Found GITHUB_TOKEN in configuration, using it to access Gtihub.")
		return github_token, nil
	}

	return "", fmt.Errorf("Github Access Token not found")
}

func loadConfiguration() error {
	path, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	path = filepath.Join(path, homeRelativeConfigPath)

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("config deserialization failed: %w", err)
	}

	globalConfig = &config
	return nil
}

func persistConfiguration() error {
	data, err := yaml.Marshal(globalConfig)
	if err != nil {
		return fmt.Errorf("config serialization failed: %w", err)
	}

	path, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	path = filepath.Join(path, homeRelativeConfigPath)

	err = os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		logger.Debugf("Error while creatinng directory %s %v", filepath.Dir(path), err)
	}
	return ioutil.WriteFile(path, data, 0600)
}
