package fix

import (
	"context"
	"fmt"

	gh "github.com/google/go-github/v70/github"

	"github.com/safedep/vet/v2/internal/github"
)

// GitHubResolver resolves refs through the GitHub API.
type GitHubResolver struct {
	Client *gh.Client
}

// ResolveSHA returns the commit SHA of a tag or a branch.
func (r GitHubResolver) ResolveSHA(ctx context.Context, owner, repo, ref string) (string, error) {
	sha, _, err := r.Client.Repositories.GetCommitSHA1(ctx, owner, repo, ref, "")
	if err != nil {
		return "", fmt.Errorf("resolve %s/%s@%s: %w", owner, repo, ref, err)
	}
	if !github.IsCommitSHA(sha) {
		return "", fmt.Errorf("resolve %s/%s@%s: the API returned %q, not a commit SHA", owner, repo, ref, sha)
	}
	return sha, nil
}
