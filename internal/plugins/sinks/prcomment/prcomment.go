package prcomment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/ci"
	"github.com/safedep/vet/v2/internal/ci/githubci"
	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/overview"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the format name.
const Name = "pr-comment"

// The values of the create option.
const (
	// CreateChanges creates a comment when the change adds, upgrades or
	// removes a package or a workflow, or has a finding.
	CreateChanges = "changes"
	// CreateFindings creates a comment only when the change has a finding.
	CreateFindings = "findings"
)

// Options are the options of the format.
type Options struct {
	// Create decides when vet creates a new comment. vet always edits a
	// comment that exists, so a resolved finding shows.
	Create string `json:"create" jsonschema:"enum=changes,enum=findings"`
}

// Sink writes and publishes the pull request comment.
type Sink struct {
	create  string
	attacks []string
	getenv  func(string) string
	// commenter returns the adapter of the platform of a run.
	commenter func(ctx context.Context, c ci.Context) (ci.Commenter, error)
}

// New builds the sink from its options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	switch o.Create {
	case "":
		o.Create = CreateChanges
	case CreateChanges, CreateFindings:
	default:
		return nil, fmt.Errorf("pr-comment: create must be %s or %s, got %q", CreateChanges, CreateFindings, o.Create)
	}
	attacks, err := controls.AttackIDs()
	if err != nil {
		return nil, err
	}
	return &Sink{create: o.Create, attacks: attacks, getenv: os.Getenv, commenter: platformCommenter}, nil
}

// platformCommenter returns the adapter of the CI platform. The GitHub
// adapter uses the token of the run.
func platformCommenter(ctx context.Context, c ci.Context) (ci.Commenter, error) {
	switch c.Platform {
	case ci.PlatformGitHub:
		client, err := github.NewClient(ctx, github.DefaultProvider(), c.APIURL, &http.Client{Timeout: 30 * time.Second})
		if err != nil {
			return nil, err
		}
		return githubci.New(ctx, c, client)
	}
	return nil, fmt.Errorf("vet cannot post a comment on %s", c.Platform)
}

// errNoChange is the reason that --report pr-comment publishes nothing
// outside a pull request.
var errNoChange = errors.New("vet posts the comment only in a pull request run of GitHub Actions")

// Publish posts the comment on the pull request of the CI run, or edits
// the comment of an earlier run. It returns the URL of the comment, or ""
// when the create option says to post nothing.
func (s *Sink) Publish(ctx context.Context, r plugin.Report) (string, error) {
	run, ok, err := ci.Detect(s.getenv)
	if err != nil {
		return "", err
	}
	if !ok || run.Change == nil {
		return "", errNoChange
	}
	c, err := s.input(ctx, r)
	if err != nil {
		return "", err
	}
	c.links = linksOf(run)
	cm, err := s.commenter(ctx, run)
	if err != nil {
		return "", err
	}
	old, err := cm.Find(ctx, marker)
	if err != nil {
		return "", err
	}
	if old == nil && !s.creates(c) {
		return "", nil
	}
	if old != nil {
		if st, ok := decodeState(old.Body); ok {
			c.old = &st
		}
	}
	return cm.Upsert(ctx, old, c.body())
}

// creates reports whether a run with no comment yet posts one.
func (s *Sink) creates(c *input) bool {
	if len(c.view.Findings) > 0 {
		return true
	}
	ch := c.view.Changes
	return s.create == CreateChanges && (ch.Packages > 0 || ch.Workflows > 0)
}

// OptionsSchema returns the JSON Schema of the options.
func (*Sink) OptionsSchema() []byte { return optschema.Of(&Options{}) }

// Write writes the comment body. It reads the CI context for the links,
// and it has no state of an earlier run.
func (s *Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	c, err := s.input(ctx, r)
	if err != nil {
		return err
	}
	if ctxCI, ok, err := ci.Detect(s.getenv); ok && err == nil {
		c.links = linksOf(ctxCI)
	}
	_, err = io.WriteString(w, c.body())
	return err
}

// input reads what the comment shows from the report.
func (s *Sink) input(ctx context.Context, r plugin.Report) (*input, error) {
	view, err := overview.Read(ctx, r)
	if err != nil {
		return nil, err
	}
	return &input{
		header: r.Header(), trailer: r.Trailer(), view: view,
		attack:  func(f *finding.Finding) bool { return slices.Contains(s.attacks, f.ControlID) },
		dialect: githubDialect,
	}, nil
}

var (
	_ plugin.Publisher = (*Sink)(nil)
	_ plugin.Schemer   = (*Sink)(nil)
)
