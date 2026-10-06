// Package ci reads the CI platform that runs vet, and the change that it
// builds. The adapters that write to a platform, such as the pull request
// comment, live in a package for each platform under internal/ci.
package ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Platform names a CI platform.
type Platform string

// PlatformGitHub is GitHub Actions.
const PlatformGitHub Platform = "github"

// Context is the CI run that runs vet.
type Context struct {
	Platform Platform
	// Repository is owner/name.
	Repository string
	ServerURL  string
	APIURL     string
	// RunURL is the page of the run, with its logs and its summary.
	RunURL string
	// Workspace is the directory of the checkout.
	Workspace string
	// Output is the file of the step outputs, or "".
	Output string
	// Change is the pull request of the run, or nil for a push or a
	// schedule.
	Change *Change
}

// SetOutput appends name=value to the file of the step outputs. It does
// nothing when the run has no such file.
func (c Context) SetOutput(name, value string) (err error) {
	if c.Output == "" {
		return nil
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("the step output %s holds a line break", name)
	}
	f, err := os.OpenFile(c.Output, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("write the step output: %w", err)
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	_, err = fmt.Fprintf(f, "%s=%s\n", name, value)
	return err
}

// Change is a pull request.
type Change struct {
	Number  int
	BaseSHA string
	HeadSHA string
	// HeadRepository is owner/name of the repository of the head branch.
	HeadRepository string
	// Fork is true when the head branch is in another repository. The
	// token of a fork run cannot write to the base repository.
	Fork bool
	// Private is true for a private base repository.
	Private bool
}

// ErrNoWriteAccess means that the token of the run cannot write a comment,
// for example the read-only token of a fork run.
var ErrNoWriteAccess = errors.New("the CI token cannot write a comment")

// Comment is a comment on a change.
type Comment struct {
	ID   string
	Body string
	URL  string
}

// Commenter finds and writes the one comment of vet on a change.
type Commenter interface {
	// Find returns the comment that holds marker, or nil.
	Find(ctx context.Context, marker string) (*Comment, error)
	// Upsert creates the comment when old is nil, else it edits old. It
	// returns the URL of the comment.
	Upsert(ctx context.Context, old *Comment, body string) (string, error)
}

// Detect reads the CI context from the environment. It is false when vet
// does not run on a CI platform that it knows. An error means a known
// platform with an event that vet cannot read.
func Detect(getenv func(string) string) (Context, bool, error) {
	if getenv("GITHUB_ACTIONS") != "true" {
		return Context{}, false, nil
	}
	c, err := detectGitHub(getenv)
	return c, true, err
}

func detectGitHub(getenv func(string) string) (Context, error) {
	c := Context{
		Platform:   PlatformGitHub,
		Repository: getenv("GITHUB_REPOSITORY"),
		ServerURL:  strings.TrimRight(getenv("GITHUB_SERVER_URL"), "/"),
		APIURL:     strings.TrimRight(getenv("GITHUB_API_URL"), "/"),
		Workspace:  getenv("GITHUB_WORKSPACE"),
		Output:     getenv("GITHUB_OUTPUT"),
	}
	if run := getenv("GITHUB_RUN_ID"); run != "" && c.ServerURL != "" && c.Repository != "" {
		c.RunURL = c.ServerURL + "/" + c.Repository + "/actions/runs/" + run
	}
	path := getenv("GITHUB_EVENT_PATH")
	if path == "" || !strings.HasPrefix(getenv("GITHUB_EVENT_NAME"), "pull_request") {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read the GitHub event: %w", err)
	}
	var ev githubEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		return c, fmt.Errorf("read the GitHub event %s: %w", path, err)
	}
	pr := ev.PullRequest
	if pr == nil || pr.Number == 0 {
		return c, nil
	}
	c.Change = &Change{
		Number:  pr.Number,
		BaseSHA: pr.Base.SHA,
		HeadSHA: pr.Head.SHA,
		Private: ev.Repository.Private,
		// A fork whose repository is gone has no head repository.
		Fork: pr.Head.Repo == nil || pr.Head.Repo.FullName != ev.Repository.FullName,
	}
	if pr.Head.Repo != nil {
		c.Change.HeadRepository = pr.Head.Repo.FullName
	}
	return c, nil
}

type githubEvent struct {
	PullRequest *struct {
		Number int `json:"number"`
		Base   struct {
			SHA string `json:"sha"`
		} `json:"base"`
		Head struct {
			SHA  string `json:"sha"`
			Repo *struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"`
		Private  bool   `json:"private"`
	} `json:"repository"`
}
