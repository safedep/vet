// Package actionrefs is the enricher that checks the commit of a GitHub
// Actions package pinned to a SHA. GitHub serves each commit of a fork
// network through each repository of the network, so a pinned SHA can come
// from a fork that an attacker controls. The enricher finds a branch or a
// tag of the named repository that contains the commit.
package actionrefs

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	gh "github.com/google/go-github/v70/github"

	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the registered name of the enricher and its config key.
const Name = "actionrefs"

// Version changes when the mapping changes, so the cache drops old results.
const Version = "1"

// The default call budget for one repository. An impostor commit needs a
// compare with each distinct commit of the branches and the tags, and an
// anonymous client gets 60 calls an hour.
const (
	anonymousMaxCalls = 50
	tokenMaxCalls     = 500
)

const pageSize = 100

// Options are plugins.actionrefs.options.
type Options struct {
	// MaxCalls bounds the GitHub API calls for one repository in a scan.
	// The default is 50 with no token and 500 with a token.
	MaxCalls *int `json:"max_calls"`
}

// Enricher sets model.Package.Action.
type Enricher struct {
	tokens   github.TokenProvider
	apiURL   string
	maxCalls int

	mu     sync.Mutex
	client *gh.Client
	repos  map[string]*repo
	// halt is a rate limit. It stops the calls for the rest of the scan.
	halt error
}

// New builds the enricher from its options. It calls the GitHub API at
// apiURL with the token of tokens, or anonymously when tokens has none.
func New(cfg plugin.Config, tokens github.TokenProvider, apiURL string) (*Enricher, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	e := &Enricher{tokens: tokens, apiURL: apiURL, repos: map[string]*repo{}}
	if o.MaxCalls != nil {
		if *o.MaxCalls < 1 {
			return nil, fmt.Errorf("%s: max_calls must be 1 or more, got %d", Name, *o.MaxCalls)
		}
		e.maxCalls = *o.MaxCalls
	}
	return e, nil
}

// CacheVersion returns Version with the API URL. The refs of one
// owner/repo differ on github.com and on a GitHub Enterprise server, so the
// cache keeps the results of each server apart.
func (e *Enricher) CacheVersion() string {
	return Version + "+" + strings.TrimRight(cmp.Or(e.apiURL, "https://api.github.com"), "/")
}

// OptionsSchema returns the JSON Schema of the options.
func (e *Enricher) OptionsSchema() []byte { return optschema.Of(&Options{}) }

// Enrich checks each GitHub Actions package of the batch that is pinned to
// a commit. A package that it cannot check gets no data, and the batch
// returns one plugin.UnavailableError that names the fix.
func (e *Enricher) Enrich(ctx context.Context, pkgs []*model.Package) error {
	var todo []*model.Package
	for _, p := range pkgs {
		if p.ID.Ecosystem() == model.EcosystemGitHubActions && github.IsCommitSHA(p.ID.RawVersion()) {
			todo = append(todo, p)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.client == nil {
		if err := e.connect(ctx); err != nil {
			return plugin.UnavailableError(fmt.Sprintf("vet did not check the pinned commits of the actions, because it could not read the GitHub token. The error is %v.", err))
		}
	}
	failed := failures{maxCalls: e.maxCalls}
	for _, p := range todo {
		r := e.repo(p.ID.RawName())
		if r.err != nil {
			failed.add(r.err, r.slug())
			continue
		}
		a, err := e.check(ctx, r, strings.ToLower(p.ID.RawVersion()))
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			// The budget can still answer a commit that a tag points
			// to. Another error stops the checks of the repository.
			if !errors.Is(err, errBudget) {
				r.err = err
			}
			failed.add(err, r.slug())
			continue
		}
		p.Action = a
	}
	return failed.err()
}

// connect builds the client, and sets the default budget from the token.
func (e *Enricher) connect(ctx context.Context) error {
	var token string
	if e.tokens != nil {
		t, err := e.tokens.Token(ctx)
		if err != nil && !errors.Is(err, github.ErrNoToken) {
			return err
		}
		token = t
	}
	c, err := github.NewClient(ctx, fixedToken(token), e.apiURL, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		return err
	}
	if e.maxCalls == 0 {
		e.maxCalls = anonymousMaxCalls
		if token != "" {
			e.maxCalls = tokenMaxCalls
		}
	}
	e.client = c
	return nil
}

type fixedToken string

func (t fixedToken) Token(context.Context) (string, error) {
	if t == "" {
		return "", github.ErrNoToken
	}
	return string(t), nil
}

func (e *Enricher) repo(name string) *repo {
	key := strings.ToLower(name)
	r := e.repos[key]
	if r == nil {
		owner, repoName, _ := strings.Cut(name, "/")
		r = &repo{owner: owner, name: repoName}
		e.repos[key] = r
	}
	return r
}

// check finds a branch or a tag that contains the commit, cheapest first:
// a tag or a branch that points to it, the default branch, then each other
// branch and tag. It compares each distinct commit of the refs once. It
// returns errBudget when the budget runs out first.
func (e *Enricher) check(ctx context.Context, r *repo, sha string) (*model.ActionCommit, error) {
	tags, err := e.tags(ctx, r)
	if err != nil {
		return nil, err
	}
	var at []string
	for _, t := range tags {
		if t.sha == sha {
			at = append(at, t.name)
		}
	}
	if len(at) > 0 {
		return &model.ActionCommit{Reachable: true, Tags: at, Ref: at[0]}, nil
	}
	branches, err := e.branches(ctx, r)
	if err != nil {
		return nil, err
	}
	for _, b := range branches {
		if b.sha == sha {
			return &model.ActionCommit{Reachable: true, Ref: b.name}, nil
		}
	}
	known, err := e.known(ctx, r, sha)
	if err != nil {
		return nil, err
	}
	if !known {
		return &model.ActionCommit{Reachable: false}, nil
	}
	def, err := e.defaultBranch(ctx, r)
	if err != nil {
		return nil, err
	}
	var refs []ref
	for _, b := range branches {
		if b.name == def {
			refs = append(refs, b)
		}
	}
	for _, b := range branches {
		if b.name != def {
			refs = append(refs, b)
		}
	}
	refs = append(refs, tags...)
	compared := map[string]bool{}
	for _, ref := range refs {
		if compared[ref.sha] {
			continue
		}
		compared[ref.sha] = true
		ok, err := e.contains(ctx, r, ref.sha, sha)
		if err != nil {
			return nil, err
		}
		if ok {
			return &model.ActionCommit{Reachable: true, Ref: ref.name}, nil
		}
	}
	return &model.ActionCommit{Reachable: false}, nil
}

// known reports whether the fork network of the repository has the commit.
// GitHub cannot run a commit that it does not have, and no ref contains it.
func (e *Enricher) known(ctx context.Context, r *repo, sha string) (bool, error) {
	_, _, err := call(e, r, func() (string, *gh.Response, error) {
		return e.client.Repositories.GetCommitSHA1(ctx, r.owner, r.name, sha, "")
	})
	if status(err) == http.StatusNotFound || status(err) == http.StatusUnprocessableEntity {
		return false, nil
	}
	return err == nil, err
}

// contains reports whether the commit base contains the commit sha. The
// compare of base with sha is then behind or identical. A 404 means that
// the two commits have no common history, as with an orphan branch.
func (e *Enricher) contains(ctx context.Context, r *repo, base, sha string) (bool, error) {
	res, _, err := call(e, r, func() (*gh.CommitsComparison, *gh.Response, error) {
		return e.client.Repositories.CompareCommits(ctx, r.owner, r.name, base, sha, &gh.ListOptions{PerPage: 1})
	})
	if status(err) == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s := res.GetStatus()
	return s == "behind" || s == "identical", nil
}

// status returns the HTTP status of a GitHub API error, or 0.
func status(err error) int {
	var resp *gh.ErrorResponse
	if errors.As(err, &resp) && resp.Response != nil {
		return resp.Response.StatusCode
	}
	return 0
}

func (e *Enricher) tags(ctx context.Context, r *repo) ([]ref, error) {
	if r.tags != nil {
		return r.tags, nil
	}
	tags, err := github.ListAll(func(page int) ([]*gh.RepositoryTag, *gh.Response, error) {
		return call(e, r, func() ([]*gh.RepositoryTag, *gh.Response, error) {
			return e.client.Repositories.ListTags(ctx, r.owner, r.name, &gh.ListOptions{Page: page, PerPage: pageSize})
		})
	})
	if err != nil {
		return nil, err
	}
	r.tags = make([]ref, 0, len(tags))
	for _, t := range tags {
		r.tags = append(r.tags, ref{name: t.GetName(), sha: strings.ToLower(t.GetCommit().GetSHA())})
	}
	return r.tags, nil
}

func (e *Enricher) branches(ctx context.Context, r *repo) ([]ref, error) {
	if r.branches != nil {
		return r.branches, nil
	}
	branches, err := github.ListAll(func(page int) ([]*gh.Branch, *gh.Response, error) {
		return call(e, r, func() ([]*gh.Branch, *gh.Response, error) {
			opts := &gh.BranchListOptions{ListOptions: gh.ListOptions{Page: page, PerPage: pageSize}}
			return e.client.Repositories.ListBranches(ctx, r.owner, r.name, opts)
		})
	})
	if err != nil {
		return nil, err
	}
	r.branches = make([]ref, 0, len(branches))
	for _, b := range branches {
		r.branches = append(r.branches, ref{name: b.GetName(), sha: strings.ToLower(b.GetCommit().GetSHA())})
	}
	return r.branches, nil
}

func (e *Enricher) defaultBranch(ctx context.Context, r *repo) (string, error) {
	if r.defaultBranch != "" {
		return r.defaultBranch, nil
	}
	info, _, err := call(e, r, func() (*gh.Repository, *gh.Response, error) {
		return e.client.Repositories.Get(ctx, r.owner, r.name)
	})
	r.defaultBranch = info.GetDefaultBranch()
	return r.defaultBranch, err
}

// call makes one API call on the budget of the repository. A rate limit
// halts the calls of each repository.
func call[T any](e *Enricher, r *repo, fn func() (T, *gh.Response, error)) (T, *gh.Response, error) {
	var zero T
	if e.halt != nil {
		return zero, nil, e.halt
	}
	if r.calls >= e.maxCalls {
		return zero, nil, errBudget
	}
	r.calls++
	v, resp, err := fn()
	var rate *gh.RateLimitError
	var abuse *gh.AbuseRateLimitError
	if errors.As(err, &rate) || errors.As(err, &abuse) {
		e.halt = err
	}
	return v, resp, err
}

// errBudget is a check that needs more calls than max_calls allows.
var errBudget = errors.New("call budget")

// repo is what the enricher learned about one repository in this scan.
type repo struct {
	owner, name   string
	calls         int
	tags          []ref
	branches      []ref
	defaultBranch string
	err           error
}

func (r *repo) slug() string { return r.owner + "/" + r.name }

type ref struct{ name, sha string }

// failures groups the repositories that the enricher could not check by
// the reason.
type failures struct {
	maxCalls int
	reasons  []string
	repos    map[string][]string
	token    bool
	budget   bool
}

func (f *failures) add(err error, repo string) {
	var reason string
	if errors.Is(err, errBudget) {
		reason = fmt.Sprintf("the budget of %d GitHub API calls ran out", f.maxCalls)
		f.budget = true
	} else {
		var token bool
		reason, token = github.Reason(err)
		f.token = f.token || token
	}
	if f.repos == nil {
		f.repos = map[string][]string{}
	}
	if _, ok := f.repos[reason]; !ok {
		f.reasons = append(f.reasons, reason)
	}
	if !slices.Contains(f.repos[reason], repo) {
		f.repos[reason] = append(f.repos[reason], repo)
	}
}

func (f *failures) err() error {
	if len(f.reasons) == 0 {
		return nil
	}
	msg := []string{"vet did not check the pinned commits of some actions."}
	for _, reason := range f.reasons {
		msg = append(msg, fmt.Sprintf("The check of %s stopped with this reason: %s.", strings.Join(f.repos[reason], ", "), reason))
	}
	if f.token {
		msg = append(msg, "Set GITHUB_TOKEN or run gh auth login to raise the rate limit.")
	}
	if f.budget {
		msg = append(msg, "Raise plugins.actionrefs.options.max_calls to check more refs.")
	}
	msg = append(msg, "Set plugins.actionrefs.enabled to false to turn off the check.")
	return plugin.UnavailableError(strings.Join(msg, " "))
}

var (
	_ plugin.Enricher = (*Enricher)(nil)
	_ plugin.Schemer  = (*Enricher)(nil)
)
