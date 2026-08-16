package nvimplugin

import (
	"net/url"
	"strings"
)

// Ecosystem labels for plugin.ecosystem metadata (not the proto
// package.v1.Ecosystem enum; the backend resolves those via purl).
const (
	ecosystemGitHub    = "github"
	ecosystemGitLab    = "gitlab"
	ecosystemBitbucket = "bitbucket"
	// ecosystemGit is the fallback for unrecognised hosts: no canonical
	// purl type, so plugin.purl is omitted for it.
	ecosystemGit = "git"
)

var hostEcosystem = map[string]string{
	"github.com":    ecosystemGitHub,
	"gitlab.com":    ecosystemGitLab,
	"bitbucket.org": ecosystemBitbucket,
}

// repoInfo is a plugin's upstream repository identity, derived from its
// clone's remote.origin.url.
type repoInfo struct {
	Repository string // canonical credential-stripped https URL; empty when unparseable
	Ecosystem  string // github | gitlab | bitbucket | git
	Owner      string // namespace path (includes subgroups for nested GitLab)
	Repo       string // final path segment
}

// normalizeRepoURL parses a git remote URL (scp-like SSH, ssh://, or
// https://) into a repoInfo. Embedded userinfo is stripped
// unconditionally: a PAT-bearing clone URL must not reach plugin.repository.
// An unparseable URL yields the zero repoInfo.
func normalizeRepoURL(raw string) repoInfo {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return repoInfo{}
	}

	host, hostname, path := splitHostPath(raw)
	if host == "" {
		return repoInfo{}
	}

	host = strings.ToLower(host)
	hostname = strings.ToLower(hostname)
	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.Trim(path, "/")
	if path == "" {
		return repoInfo{}
	}

	owner, repo := splitOwnerRepo(path)

	// Ecosystem keys off the bare hostname; the Repository URL keeps any
	// explicit port so a non-default host is not misidentified.
	ecosystem, ok := hostEcosystem[hostname]
	if !ok {
		ecosystem = ecosystemGit
	}

	return repoInfo{
		Repository: "https://" + host + "/" + path,
		Ecosystem:  ecosystem,
		Owner:      owner,
		Repo:       repo,
	}
}

// splitHostPath extracts host, bare hostname, and path from a git remote
// URL, discarding scheme and userinfo. host keeps any explicit port
// (u.Host excludes userinfo but retains host:port); hostname is the
// portless form used for ecosystem lookup. Handles scp-like syntax
// (user@host:path), which is not a valid URL and carries no port.
func splitHostPath(raw string) (host, hostname, path string) {
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", "", ""
		}
		return u.Host, u.Hostname(), u.Path
	}

	if i := strings.Index(raw, ":"); i >= 0 {
		hostPart := raw[:i]
		path = raw[i+1:]
		if at := strings.LastIndex(hostPart, "@"); at >= 0 {
			hostPart = hostPart[at+1:]
		}
		return hostPart, hostPart, path
	}

	return "", "", ""
}

// splitOwnerRepo splits owner/repo (or group/subgroup/project) into the
// owner namespace and final project segment.
func splitOwnerRepo(path string) (owner, repo string) {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[:i], path[i+1:]
	}
	return "", path
}

// buildPurl constructs a canonical purl, or "" when no purl type applies
// (ecosystemGit). Built directly rather than via pkg/common/purl, whose
// mapper associates the github type with the GitHub Actions ecosystem.
func buildPurl(info repoInfo, commit string) string {
	switch info.Ecosystem {
	case ecosystemGitHub, ecosystemGitLab, ecosystemBitbucket:
	default:
		return ""
	}
	if info.Owner == "" || info.Repo == "" {
		return ""
	}

	purl := "pkg:" + info.Ecosystem + "/" + info.Owner + "/" + info.Repo
	if commit != "" {
		purl += "@" + commit
	}
	return purl
}
