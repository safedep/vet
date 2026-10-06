// Package githubci writes the pull request comment of vet on GitHub with
// the REST API and the token of the run.
package githubci

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
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
	// output is the GITHUB_OUTPUT file of the step, or "".
	output string
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
	cm := &Commenter{client: client, owner: owner, repo: repo, number: c.Change.Number, output: os.Getenv("GITHUB_OUTPUT")}
	// A personal token can read its user. The token of an app cannot, and
	// its comments come from a bot account.
	if u, _, err := client.Users.Get(ctx, ""); err == nil {
		cm.tokenUser = u.GetLogin()
	}
	return cm, nil
}

// Find returns the first comment that holds marker and that vet wrote: a
// comment of a bot account or of the user of the token. A contributor
// cannot post a comment that vet then edits or reads state from.
func (c *Commenter) Find(ctx context.Context, marker string) (*ci.Comment, error) {
	comments, err := github.ListAll(func(page int) ([]*gh.IssueComment, *gh.Response, error) {
		return c.client.Issues.ListComments(ctx, c.owner, c.repo, c.number, &gh.IssueListCommentsOptions{ListOptions: gh.ListOptions{Page: page, PerPage: 100}})
	})
	if err != nil {
		return nil, fmt.Errorf("github: list the comments: %w", err)
	}
	for _, cm := range comments {
		if strings.Contains(cm.GetBody(), marker) && c.ours(cm.GetUser()) {
			return &ci.Comment{ID: strconv.FormatInt(cm.GetID(), 10), Body: cm.GetBody(), URL: cm.GetHTMLURL()}, nil
		}
	}
	return nil, nil
}

func (c *Commenter) ours(u *gh.User) bool {
	return u.GetType() == "Bot" || (c.tokenUser != "" && u.GetLogin() == c.tokenUser)
}

// Upsert creates the comment, or edits it when the body differs. It
// writes comment-url to the GITHUB_OUTPUT file of the step.
func (c *Commenter) Upsert(ctx context.Context, old *ci.Comment, body string) (string, error) {
	url, err := c.upsert(ctx, old, body)
	if err != nil {
		return "", err
	}
	return url, c.setOutput("comment-url", url)
}

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
	if resp != nil && resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("%w: %v", ci.ErrNoWriteAccess, err)
	}
	if err != nil {
		return "", fmt.Errorf("github: write the comment: %w", err)
	}
	return cm.GetHTMLURL(), nil
}

// setOutput appends name=value to the GITHUB_OUTPUT file, when the step
// has one.
func (c *Commenter) setOutput(name, value string) (err error) {
	if c.output == "" {
		return nil
	}
	f, err := os.OpenFile(c.output, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("github: write the step output: %w", err)
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	_, err = fmt.Fprintf(f, "%s=%s\n", name, value)
	return err
}

var _ ci.Commenter = (*Commenter)(nil)
