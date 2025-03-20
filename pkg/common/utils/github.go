package utils

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/safedep/dry/adapters"
)

var commitHashRegex = regexp.MustCompile(`^[a-f0-9]{40}$`)

func CreateGitHubAdapter() (*adapters.GithubClient, error) {
	gha, err := adapters.NewGithubClient(adapters.DefaultGitHubClientConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub client: %v", err)
	}

	return gha, nil
}

// ResolveGitHubRepositoryCommitSHA resolves the commit SHA for a given repository and version
// If the version is empty, it will resolve the default branch
func ResolveGitHubRepositoryCommitSHA(ctx context.Context, gha *adapters.GithubClient,
	owner, repo, version string,
) (string, error) {
	if version == "" {
		repoInfo, _, err := gha.Client.Repositories.Get(ctx, owner, repo)
		if err != nil {
			return "", fmt.Errorf("failed to get repository info: %v", err)
		}

		version = repoInfo.GetDefaultBranch()
	}

	// Check if version is a commit hash
	if commitHashRegex.MatchString(strings.ToLower(version)) {
		return version, nil
	}

	// Resolve version as a commit hash
	commit, _, err := gha.Client.Repositories.GetCommit(ctx, owner, repo, version, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get commit: %v", err)
	}

	return commit.GetSHA(), nil
}
