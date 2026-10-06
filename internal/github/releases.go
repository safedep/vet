package github

import (
	"context"
	"fmt"
	"strings"
	"time"

	gh "github.com/google/go-github/v70/github"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// Release is a release of a repository, with the fields that a release
// choice reads. go-github has no immutable field, so vet decodes the API
// answer itself.
type Release struct {
	Tag         string    `json:"tag_name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	Immutable   bool      `json:"immutable"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

// Asset is a file of a release.
type Asset struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListReleases returns each release of owner/repo. It never reads the
// latest release of the repository, which can belong to another major
// version.
func ListReleases(ctx context.Context, client *gh.Client, owner, repo string) ([]Release, error) {
	return ListAll(func(page int) ([]Release, *gh.Response, error) {
		req, err := client.NewRequest("GET", fmt.Sprintf("repos/%s/%s/releases?per_page=100&page=%d", owner, repo, page), nil)
		if err != nil {
			return nil, nil, err
		}
		var out []Release
		resp, err := client.Do(ctx, req, &out)
		return out, resp, err
	})
}

// Choice is the rule that picks a release.
type Choice struct {
	// Major is the major version, such as v2.
	Major string
	// Prerelease takes a pre-release too.
	Prerelease bool
	// Immutable takes only a release that GitHub marks immutable.
	Immutable bool
	// Cooldown skips a release that is younger. The age counts from the
	// latest of the publish time and the asset update times.
	Cooldown time.Duration
	// Minimum skips a release below this version, or "".
	Minimum string
	Now     time.Time
}

// Newest returns the newest release that the choice takes, or false.
func (c Choice) Newest(releases []Release) (Release, bool) {
	var best Release
	var bestV string
	for _, r := range releases {
		v := SemverOf(r.Tag)
		switch {
		case v == "" || r.Draft || module.IsPseudoVersion(v):
		case semver.Major(v) != c.Major:
		case (r.Prerelease || semver.Prerelease(v) != "") && !c.Prerelease:
		case c.Immutable && !r.Immutable:
		case c.Minimum != "" && semver.Compare(v, SemverOf(c.Minimum)) < 0:
		case c.Now.Sub(r.youngest()) < c.Cooldown:
		case bestV == "" || semver.Compare(v, bestV) > 0:
			best, bestV = r, v
		}
	}
	return best, bestV != ""
}

// youngest returns the latest of the publish time and the asset update
// times. A change to an old release makes it young again.
func (r Release) youngest() time.Time {
	t := r.PublishedAt
	for _, a := range r.Assets {
		if a.UpdatedAt.After(t) {
			t = a.UpdatedAt
		}
	}
	return t
}

// SemverOf returns the version in the form of golang.org/x/mod/semver, with
// the leading v, or "" for a version that is not valid. A release build
// sets the version with no v.
func SemverOf(v string) string {
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return v
}
