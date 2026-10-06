package prcomment

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/ci"
	"github.com/safedep/vet/v2/internal/ci/githubci"
	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/overview"
	"github.com/safedep/vet/v2/internal/plugins/cloud/ghcp"
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
	// Proxy posts the comment of a fork run of a public repository through
	// the SafeDep comment proxy. The default is true.
	Proxy *bool `json:"proxy"`
	// ProxyURL is the address of the comment proxy.
	ProxyURL string `json:"proxy_url"`
	// Key keeps apart the comments of two vet steps on one pull request,
	// for example a step for each service of a monorepo.
	Key string `json:"key" jsonschema:"pattern=^[a-z0-9-]*$"`
}

// Sink writes and publishes the pull request comment.
type Sink struct {
	create  string
	key     string
	attacks []string
	getenv  func(string) string
	// commenter returns the adapter of the platform of a run.
	commenter func(ctx context.Context, c ci.Context) (ci.Commenter, error)
	// proxy returns the adapter of the comment proxy, or nil when the
	// option turns it off. read finds the comment with the run token.
	proxy func(ctx context.Context, c ci.Context, read ci.Commenter) (ci.Commenter, error)
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
	if !validKey.MatchString(o.Key) {
		return nil, fmt.Errorf("pr-comment: key must hold only a-z, 0-9 and -, got %q", o.Key)
	}
	s := &Sink{create: o.Create, key: o.Key, attacks: attacks, getenv: os.Getenv, commenter: platformCommenter}
	if o.Proxy == nil || *o.Proxy {
		s.proxy = proxyCommenter(cmp.Or(o.ProxyURL, ghcp.DefaultURL), ghcp.Tag+strings.TrimSuffix("-"+o.Key, "-"))
	}
	return s, nil
}

var validKey = regexp.MustCompile(`^[a-z0-9-]*$`)

// proxyCommenter returns the factory of the comment proxy at url, for the
// comment with tag. The proxy takes the token of the run.
func proxyCommenter(url, tag string) func(context.Context, ci.Context, ci.Commenter) (ci.Commenter, error) {
	return func(ctx context.Context, c ci.Context, read ci.Commenter) (ci.Commenter, error) {
		token, err := github.DefaultProvider().Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("the comment proxy needs the token of the run: %w", err)
		}
		return ghcp.New(url, token, tag, c, read)
	}
}

// viaProxy is the footer line of a comment that the proxy posts.
const viaProxy = "Posted by the SafeDep comment proxy, because the workflow token of a fork cannot write comments."

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
	c.links = linksOf(run, r.Header().Scan.Target)
	cm, err := s.commenter(ctx, run)
	if err != nil {
		return "", err
	}
	old, err := cm.Find(ctx, c.marker)
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
	url, err := cm.Upsert(ctx, old, c.body())
	if errors.Is(err, ci.ErrNoWriteAccess) && run.Change.Fork {
		url, err = s.publishByProxy(ctx, run, cm, old, c)
	}
	if err != nil {
		return "", err
	}
	return url, run.SetOutput("comment-url", url)
}

// publishByProxy posts the comment of a fork run through the comment
// proxy. The proxy serves public repositories only.
func (s *Sink) publishByProxy(ctx context.Context, run ci.Context, read ci.Commenter, old *ci.Comment, c *input) (url string, err error) {
	switch {
	case run.Change.Private:
		return "", errors.New("the token of a fork run of a private repository cannot write a comment. The step summary has the report")
	case s.proxy == nil:
		return "", errors.New("the token of a fork run cannot write a comment, and plugins.pr-comment.options.proxy is false. The step summary has the report")
	}
	pc, err := s.proxy(ctx, run, read)
	if err != nil {
		return "", err
	}
	if closer, ok := pc.(io.Closer); ok {
		defer func() { err = errors.Join(err, closer.Close()) }()
	}
	c.via = viaProxy
	return pc.Upsert(ctx, old, c.body())
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

// Write writes the comment body, with no links to the platform and no
// state of an earlier run.
func (s *Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	c, err := s.input(ctx, r)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, c.body())
	return err
}

// linksOf returns the links of a run. The file links need the path of the
// scan target in the checkout.
func linksOf(run ci.Context, target string) links {
	l := links{Server: run.ServerURL, Repository: run.Repository, Run: run.RunURL}
	if run.Change != nil {
		l.Head = run.Change.HeadSHA
	}
	l.Prefix, l.NoFiles = targetPrefix(run.Workspace, target)
	return l
}

// targetPrefix returns the path of target in the workspace, with a
// trailing "/", or "" for the root. noFiles is true when the target is not
// in the workspace.
func targetPrefix(workspace, target string) (prefix string, noFiles bool) {
	if workspace == "" {
		return "", true
	}
	ws, err := filepath.Abs(workspace)
	if err != nil {
		return "", true
	}
	t, err := filepath.Abs(target)
	if err != nil {
		return "", true
	}
	rel, err := filepath.Rel(ws, t)
	switch {
	case err != nil || !filepath.IsLocal(rel):
		return "", true
	case rel == ".":
		return "", false
	}
	return filepath.ToSlash(rel) + "/", false
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
		dialect: githubDialect, marker: markerOf(s.key),
	}, nil
}

var (
	_ plugin.Publisher = (*Sink)(nil)
	_ plugin.Schemer   = (*Sink)(nil)
)
