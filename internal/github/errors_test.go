package github

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	gh "github.com/google/go-github/v70/github"
	"github.com/stretchr/testify/assert"
)

func TestReason(t *testing.T) {
	answer := func(code int) error {
		return fmt.Errorf("resolve a/b@v1: %w", &gh.ErrorResponse{Response: &http.Response{StatusCode: code, Request: &http.Request{Method: "GET", URL: &url.URL{}}}, Message: "long text"})
	}
	cases := []struct {
		name   string
		err    error
		reason string
		token  bool
	}{
		{"forbidden", answer(http.StatusForbidden), "GitHub API answered 403", true},
		{"unauthorized", answer(http.StatusUnauthorized), "GitHub API answered 401", true},
		{"not found", answer(http.StatusNotFound), "GitHub API answered 404 (no such repository or ref)", false},
		{"server error", answer(http.StatusBadGateway), "GitHub API answered 502", false},
		{"rate limit", &gh.RateLimitError{Message: "x", Response: &http.Response{Request: &http.Request{Method: "GET", URL: &url.URL{}}}}, "GitHub API rate limit", true},
		{"no connection", &url.Error{Op: "Get", URL: "https://api.github.com", Err: errors.New("dial tcp: refused")}, "vet could not connect to the GitHub API", false},
		{"other", errors.New("the API returned \"x\", not a commit SHA"), "the API returned \"x\", not a commit SHA", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, token := Reason(tc.err)
			assert.Equal(t, tc.reason, reason)
			assert.Equal(t, tc.token, token)
		})
	}
}
