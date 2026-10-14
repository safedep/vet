package github

import (
	"regexp"
	"strings"

	gh "github.com/google/go-github/v70/github"
)

var commitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// IsCommitSHA reports a full commit SHA of 40 hex characters.
func IsCommitSHA(s string) bool { return commitSHA.MatchString(s) }

// IsLocalAction reports a uses: value that names a path, not another
// repository. GitHub reads ./path from the workspace and $/path from the
// commit that runs.
func IsLocalAction(uses string) bool {
	return strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, ".\\") || strings.HasPrefix(uses, "$/")
}

// ListAll calls list for each page of a GitHub API list, from the first
// page, and returns the items of all pages.
func ListAll[T any](list func(page int) ([]T, *gh.Response, error)) ([]T, error) {
	out := []T{}
	for page := 0; ; {
		items, resp, err := list(page)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if resp == nil || resp.NextPage == 0 {
			return out, nil
		}
		page = resp.NextPage
	}
}
