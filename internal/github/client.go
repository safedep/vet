package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	gh "github.com/google/go-github/v70/github"
)

// NewClient returns a GitHub API client with the provider's token. With no
// token the client is anonymous. A baseURL other than the public API points
// the client at another server, for example a test stub.
func NewClient(ctx context.Context, tp TokenProvider, baseURL string, hc *http.Client) (*gh.Client, error) {
	c := gh.NewClient(hc)
	if tp != nil {
		token, err := tp.Token(ctx)
		switch {
		case err == nil:
			c = c.WithAuthToken(token)
		case errors.Is(err, ErrNoToken):
		default:
			return nil, err
		}
	}
	if baseURL != "" && strings.TrimRight(baseURL, "/") != "https://api.github.com" {
		u := strings.TrimRight(baseURL, "/") + "/"
		var err error
		c, err = c.WithEnterpriseURLs(u, u)
		if err != nil {
			return nil, fmt.Errorf("github API URL %q: %w", baseURL, err)
		}
		// WithEnterpriseURLs adds /api/v3/ to a URL that lacks it. A stub
		// serves the public API paths at its root.
		c.BaseURL.Path = strings.TrimSuffix(c.BaseURL.Path, "api/v3/")
	}
	return c, nil
}
