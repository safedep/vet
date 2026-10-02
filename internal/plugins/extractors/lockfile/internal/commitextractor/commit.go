// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package commitextractor provides functions to extract commit hashes and repository URLs from git resolution strings.
package commitextractor

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

var (
	codeloadURLRegexp      = regexp.MustCompile(`^https?://codeload\.github\.com/([^/]+/[^/]+)/tar\.gz/`)
	gitlabArchiveURLRegexp = regexp.MustCompile(`^https?://gitlab\.com/(.+?)(?:/-/archive/|/repository/archive\.tar\.gz)`)
	scpURLRegexp           = regexp.MustCompile(`^(?:(?:git\+)?ssh://)?(?:[^@/]+@)?([^/:]+):([^/#?][^#?]*)`)

	matchers = []*regexp.Regexp{
		regexp.MustCompile(`(?:^|.+@)(?:git(?:\+(?:ssh|https))?|ssh)://.+#(\w+)$`),
		regexp.MustCompile(`(?:^|.+@)https://.+\.git#(\w+)$`),
		regexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+)+/tar\.gz/(\w+)`),
		regexp.MustCompile(`https://gitlab\.com(?:/[\w-.]+)+/-/archive/(\w+)`),
		regexp.MustCompile(`.+[#&]commit[:=](\w+)$`),
		regexp.MustCompile(`^(?:github|gitlab|bitbucket):.+#(\w+)$`),
	}
)

// TryExtractCommit attempts to extract a commit hash from a package resolution string.
func TryExtractCommit(resolution string) string {
	for _, re := range matchers {
		matched := re.FindStringSubmatch(resolution)
		if matched != nil {
			return matched[1]
		}
	}

	u, err := url.Parse(resolution)
	if err != nil {
		return ""
	}

	gitRepoHosts := []string{
		"bitbucket.org",
		"github.com",
		"gitlab.com",
	}

	if !slices.Contains(gitRepoHosts, u.Host) {
		return ""
	}

	if u.RawQuery == "" {
		return u.Fragment
	}

	queries := u.Query()
	return queries.Get("ref")
}

// NormalizeRepo normalizes various Git URL formats (SSH, HTTPS, git+, tarball archives, shorthands)
// into a standard HTTPS URL (e.g. "https://github.com/org/repo").
func NormalizeRepo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// Yarn v2 often prefixes the URL with package name: <pkg>@https:// or @<scope>/<pkg>@https://
	schemes := []string{"@https://", "@http://", "@git+https://", "@git+ssh://", "@git://", "@git+", "@ssh://"}
	for _, scheme := range schemes {
		if atIdx := strings.LastIndex(raw, scheme); atIdx != -1 {
			raw = raw[atIdx+1:]
			break
		}
	}

	shorthand := strings.TrimPrefix(raw, "git+")
	shorthand = strings.TrimPrefix(shorthand, "ssh://")
	shorthand = strings.TrimPrefix(shorthand, "git://")
	if repo, ok := strings.CutPrefix(shorthand, "github:"); ok {
		if i := strings.IndexAny(repo, "#?"); i != -1 {
			repo = repo[:i]
		}
		return "https://github.com/" + strings.TrimSuffix(repo, ".git")
	}
	if repo, ok := strings.CutPrefix(shorthand, "gitlab:"); ok {
		if i := strings.IndexAny(repo, "#?"); i != -1 {
			repo = repo[:i]
		}
		return "https://gitlab.com/" + strings.TrimSuffix(repo, ".git")
	}
	if repo, ok := strings.CutPrefix(shorthand, "bitbucket:"); ok {
		if i := strings.IndexAny(repo, "#?"); i != -1 {
			repo = repo[:i]
		}
		return "https://bitbucket.org/" + strings.TrimSuffix(repo, ".git")
	}

	if m := codeloadURLRegexp.FindStringSubmatch(raw); m != nil {
		return "https://github.com/" + m[1]
	}
	if m := gitlabArchiveURLRegexp.FindStringSubmatch(raw); m != nil {
		return "https://gitlab.com/" + m[1]
	}

	// scp-like syntax: [git+ssh://][ssh://][user@]host:owner/repo
	if m := scpURLRegexp.FindStringSubmatch(raw); m != nil {
		host := m[1]
		rest := m[2]
		path := strings.TrimSuffix(rest, ".git")
		return "https://" + host + "/" + path
	}

	cleaned := raw
	cleaned = strings.TrimPrefix(cleaned, "git+")
	cleaned = strings.TrimPrefix(cleaned, "git://")
	cleaned = strings.TrimPrefix(cleaned, "ssh://")
	if !strings.HasPrefix(cleaned, "http://") && !strings.HasPrefix(cleaned, "https://") {
		cleaned = "https://" + cleaned
	}

	u, err := url.Parse(cleaned)
	if err != nil {
		return ""
	}

	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""

	host := u.Hostname()
	path := strings.Trim(u.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	if host == "" || path == "" {
		return ""
	}

	return "https://" + host + "/" + path
}

// TryExtractRepo extracts and normalizes the repository URL from a package resolution string.
func TryExtractRepo(resolution string) string {
	res := extractRepoFromHashes(resolution)
	if res != "" {
		return NormalizeRepo(res)
	}

	return NormalizeRepo(resolution)
}

func extractRepoFromHashes(resolution string) string {
	if repo, _, ok := strings.Cut(resolution, "#"); ok {
		return repo
	}
	return ""
}
