package github

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	gh "github.com/google/go-github/v70/github"
)

// Reason returns a short reason for an error of a GitHub API call, as
// "GitHub API answered 403", and whether a token can fix it. An error that
// is not of the API keeps its text.
func Reason(err error) (reason string, token bool) {
	var rate *gh.RateLimitError
	var abuse *gh.AbuseRateLimitError
	var resp *gh.ErrorResponse
	var nerr *url.Error
	switch {
	case errors.As(err, &rate), errors.As(err, &abuse):
		return "GitHub API rate limit", true
	case errors.As(err, &resp) && resp.Response != nil:
		code := resp.Response.StatusCode
		reason := fmt.Sprintf("GitHub API answered %d", code)
		if code == http.StatusNotFound {
			reason += " (no such repository or ref)"
		}
		return reason, code == http.StatusUnauthorized || code == http.StatusForbidden
	case errors.As(err, &nerr):
		return "vet could not connect to the GitHub API", false
	}
	return err.Error(), false
}
