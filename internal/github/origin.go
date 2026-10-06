package github

import (
	"strings"

	gogit "github.com/go-git/go-git/v5"
)

// OriginRepo returns owner/repo of the github.com origin remote of the git
// repository at dir or above it, or "".
func OriginRepo(dir string) string {
	repo, err := gogit.PlainOpenWithOptions(dir, &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return ""
	}
	remote, err := repo.Remote("origin")
	if err != nil || len(remote.Config().URLs) == 0 {
		return ""
	}
	return RemoteRepo(remote.Config().URLs[0])
}

// RemoteRepo returns owner/repo of a github.com remote URL, or "".
func RemoteRepo(u string) string {
	for _, prefix := range []string{"https://github.com/", "http://github.com/", "git@github.com:", "ssh://git@github.com/"} {
		if rest, ok := strings.CutPrefix(u, prefix); ok {
			parts := strings.SplitN(strings.TrimSuffix(strings.TrimSuffix(rest, "/"), ".git"), "/", 3)
			if len(parts) >= 2 {
				return parts[0] + "/" + parts[1]
			}
		}
	}
	return ""
}
