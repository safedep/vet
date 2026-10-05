// Package actionrefs is the enricher that checks the commit of a GitHub
// Actions package pinned to a SHA. GitHub serves each commit of a fork
// network through each repository of the network, so a pinned SHA can come
// from a fork that an attacker controls. The enricher finds a branch or a
// tag of the named repository that contains the commit.
package actionrefs

import (
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

const defaultMaxCalls = 50

const pageSize = 100

// Options are plugins.actionrefs.options.
type Options struct {
	// MaxCalls bounds the GitHub API calls for one repository in a scan.
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
	e := &Enricher{tokens: tokens, apiURL: apiURL, maxCalls: defaultMaxCalls, repos: map[string]*repo{}}
	if o.MaxCalls != nil {
		if *o.MaxCalls < 1 {
			return nil, fmt.Errorf("%s: max_calls must be 1 or more, got %d", Name, *o.MaxCalls)
		}
		e.maxCalls = *o.MaxCalls
	}
	return e, nil
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
		c, err := github.NewClient(ctx, e.tokens, e.apiURL, &http.Client{Timeout: 30 * time.Second})
		if err != nil {
			return plugin.UnavailableError(fmt.Sprintf("vet did not check the pinned commits of the actions: %v.", err))
		}
		e.client = c
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
// a tag that points to it, the default branch, then each other branch and
// tag. It returns errBudget when the budget runs out first.
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
	def, err := e.defaultBranch(ctx, r)
	if err != nil {
		return nil, err
	}
	refs := []string{def}
	branches, err := e.branches(ctx, r)
	if err != nil {
		return nil, err
	}
	for _, b := range branches {
		if b != def {
			refs = append(refs, b)
		}
	}
	for _, t := range tags {
		refs = append(refs, t.name)
	}
	for _, ref := range refs {
		ok, err := e.contains(ctx, r, ref, sha)
		if errors.Is(err, errNoCommit) {
			break
		}
		if err != nil {
			return nil, err
		}
		if ok {
			return &model.ActionCommit{Reachable: true, Ref: ref}, nil
		}
	}
	return &model.ActionCommit{Reachable: false}, nil
}

// errNoCommit is a commit that the fork network does not have. No ref of
// the repository contains it.
var errNoCommit = errors.New("no such commit")

// contains reports whether ref contains the commit. The compare of ref with
// the commit is then behind or identical.
func (e *Enricher) contains(ctx context.Context, r *repo, ref, sha string) (bool, error) {
	cmp, _, err := call(e, r, func() (*gh.CommitsComparison, *gh.Response, error) {
		return e.client.Repositories.CompareCommits(ctx, r.owner, r.name, ref, sha, &gh.ListOptions{PerPage: 1})
	})
	var resp *gh.ErrorResponse
	if errors.As(err, &resp) && resp.Response != nil && resp.Response.StatusCode == http.StatusNotFound {
		return false, errNoCommit
	}
	if err != nil {
		return false, err
	}
	status := cmp.GetStatus()
	return status == "behind" || status == "identical", nil
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

func (e *Enricher) branches(ctx context.Context, r *repo) ([]string, error) {
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
	r.branches = make([]string, 0, len(branches))
	for _, b := range branches {
		r.branches = append(r.branches, b.GetName())
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
	branches      []string
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
		reason = fmt.Sprintf("The budget of %d GitHub API calls ran out", f.maxCalls)
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
		msg = append(msg, fmt.Sprintf("%s for %s.", reason, strings.Join(f.repos[reason], ", ")))
	}
	if f.token {
		msg = append(msg, "Set GITHUB_TOKEN or run gh auth login.")
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
