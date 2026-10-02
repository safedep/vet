package test

import (
	"os"
	"strconv"
	"testing"

	"github.com/google/go-github/v70/github"
)

func verifyE2E(t *testing.T) {
	s, err := strconv.ParseBool(os.Getenv("VET_E2E"))
	if (err != nil) || (!s) {
		t.Skip("E2E is disabled in the environment")
	}
}

func EnsureEndToEndTestIsEnabled(t *testing.T) {
	verifyE2E(t)
}

func newGithubClient() (*github.Client, error) {
	client := github.NewClient(nil)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		client = client.WithAuthToken(token)
	}

	return client, nil
}
