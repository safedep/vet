// Package githubci writes the pull request comment of vet on GitHub with
// the REST API and the token of the run.
package githubci

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	gh "github.com/google/go-github/v70/github"

	"github.com/safedep/vet/v2/internal/ci"
	"github.com/safedep/vet/v2/internal/github"
)

// Commenter finds and writes the comment of vet on one pull request.
type Commenter struct {
	client      *gh.Client
	owner, repo string
	number      int
	// tokenUser is the login of a personal token, or "" for the token of
	// a GitHub App such as GITHUB_TOKEN.
	tokenUser string
}

// New returns the commenter of the change of c.
func New(ctx context.Context, c ci.Context, client *gh.Client) (*Commenter, error) {
	if c.Change == nil {
		return nil, errors.New("github: the run has no pull request")
	}
	owner, repo, ok := strings.Cut(c.Repository, "/")
	if !ok {
		return nil, fmt.Errorf("github: bad repository %q", c.Repository)
	}
	cm := &Commenter{client: client, owner: owner, repo: repo, number: c.Change.Number}
	// A personal token can read its user. The token of an app, such as
	// GITHUB_TOKEN, cannot, and its comments come from a bot account.
	u, resp, err := client.Users.Get(ctx, "")
	switch {
	case err == nil:
		cm.tokenUser = u.GetLogin()
	case resp == nil || (resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized):
		return nil, fmt.Errorf("github: read the user of the token: %w", err)
	}
	return cm, nil
}

// actionsBot is the account of GITHUB_TOKEN.
const actionsBot = "github-actions[bot]"

// Find returns the newest comment that starts with marker and that vet
// wrote. A comment of the account of the token wins over a comment of
// another bot, such as the SafeDep comment proxy. A contributor cannot
// post a comment that vet then edits or reads state from.
func (c *Commenter) Find(ctx context.Context, marker string) (*ci.Comment, error) {
	comments, err := github.ListAll(func(page int) ([]*gh.IssueComment, *gh.Response, error) {
		return c.client.Issues.ListComments(ctx, c.owner, c.repo, c.number, &gh.IssueListCommentsOptions{ListOptions: gh.ListOptions{Page: page, PerPage: 100}})
	})
	if err != nil {
		return nil, fmt.Errorf("github: list the comments: %w", err)
	}
	var found *gh.IssueComment
	for _, cm := range comments {
		if !strings.HasPrefix(cm.GetBody(), marker) {
			continue
		}
		switch {
		case c.own(cm.GetUser()):
			found = cm
		case cm.GetUser().GetType() == "Bot" && (found == nil || !c.own(found.GetUser())):
			found = cm
		}
	}
	if found == nil {
		return nil, nil
	}
	return &ci.Comment{ID: strconv.FormatInt(found.GetID(), 10), Body: found.GetBody(), URL: found.GetHTMLURL()}, nil
}

// own reports whether the account of the token wrote a comment.
func (c *Commenter) own(u *gh.User) bool {
	if c.tokenUser != "" {
		return u.GetLogin() == c.tokenUser
	}
	return u.GetLogin() == actionsBot
}

// Upsert creates the comment, or edits it when the body differs. When the
// token cannot edit the old comment, for example the comment of another
// bot, it creates a new one.
func (c *Commenter) Upsert(ctx context.Context, old *ci.Comment, body string) (string, error) {
	url, err := c.upsert(ctx, old, body)
	if old != nil && (errors.Is(err, ci.ErrNoWriteAccess) || errors.Is(err, errNotFound)) {
		url, err = c.upsert(ctx, nil, body)
	}
	return url, err
}

var errNotFound = errors.New("github: the comment does not exist")

func (c *Commenter) upsert(ctx context.Context, old *ci.Comment, body string) (string, error) {
	if old != nil && old.Body == body {
		return old.URL, nil
	}
	var (
		cm   *gh.IssueComment
		resp *gh.Response
		err  error
	)
	if old == nil {
		cm, resp, err = c.client.Issues.CreateComment(ctx, c.owner, c.repo, c.number, &gh.IssueComment{Body: &body})
	} else {
		id, perr := strconv.ParseInt(old.ID, 10, 64)
		if perr != nil {
			return "", fmt.Errorf("github: bad comment id %q", old.ID)
		}
		cm, resp, err = c.client.Issues.EditComment(ctx, c.owner, c.repo, id, &gh.IssueComment{Body: &body})
	}
	var rate *gh.RateLimitError
	var abuse *gh.AbuseRateLimitError
	switch {
	case errors.As(err, &rate) || errors.As(err, &abuse):
		return "", fmt.Errorf("github: write the comment: %w", err)
	case resp != nil && resp.StatusCode == http.StatusForbidden:
		return "", fmt.Errorf("%w: %v", ci.ErrNoWriteAccess, err)
	case resp != nil && resp.StatusCode == http.StatusNotFound && old != nil:
		return "", fmt.Errorf("%w: %v", errNotFound, err)
	}
	if err != nil {
		return "", fmt.Errorf("github: write the comment: %w", err)
	}
	return cm.GetHTMLURL(), nil
}

var _ ci.Commenter = (*Commenter)(nil)
