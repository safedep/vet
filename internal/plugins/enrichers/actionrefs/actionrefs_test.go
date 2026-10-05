package actionrefs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

const (
	tagged   = "1111111111111111111111111111111111111111"
	onMain   = "2222222222222222222222222222222222222222"
	onBranch = "3333333333333333333333333333333333333333"
	onTag    = "4444444444444444444444444444444444444444"
	impostor = "5555555555555555555555555555555555555555"
	unknown  = "6666666666666666666666666666666666666666"
	headSHA  = "7777777777777777777777777777777777777777"
	oldTag   = "8888888888888888888888888888888888888888"
)

// fakeGitHub serves the GitHub API calls of the enricher for the
// repository o/r. compare maps base...head to a status. A missing pair is
// diverged, and a head of unknown is a 404.
type fakeGitHub struct {
	mu        sync.Mutex
	calls     map[string]int
	tags      map[string]string
	branches  map[string]string
	compare   map[string]string
	rateLimit bool
}

func newFake() *fakeGitHub {
	return &fakeGitHub{
		calls:    map[string]int{},
		tags:     map[string]string{"v1.0.0": tagged, "v1": tagged, "v0.9.0": oldTag},
		branches: map[string]string{"main": headSHA, "release": headSHA},
		compare: map[string]string{
			"main..." + onMain: "behind", "main..." + headSHA: "identical",
			"release..." + onBranch: "behind", "v0.9.0..." + onTag: "behind",
		},
	}
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/repos/o/r")
	kind, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	f.mu.Lock()
	f.calls[kind]++
	limited := f.rateLimit
	f.mu.Unlock()
	if limited {
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "9999999999")
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]string{"message": "API rate limit exceeded"})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/repos/o/r") {
		http.NotFound(w, r)
		return
	}
	switch {
	case path == "":
		writeJSON(w, map[string]string{"default_branch": "main"})
	case path == "/tags":
		writeJSON(w, refs(f.tags))
	case path == "/branches":
		writeJSON(w, refs(f.branches))
	case strings.HasPrefix(path, "/compare/"):
		pair := strings.TrimPrefix(path, "/compare/")
		if strings.HasSuffix(pair, unknown) {
			http.NotFound(w, r)
			return
		}
		status := f.compare[pair]
		if status == "" {
			status = "diverged"
		}
		writeJSON(w, map[string]string{"status": status})
	default:
		http.NotFound(w, r)
	}
}

func refs(m map[string]string) []map[string]any {
	out := []map[string]any{}
	for name, sha := range m {
		out = append(out, map[string]any{"name": name, "commit": map[string]string{"sha": sha}})
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}

func newEnricher(t *testing.T, f *fakeGitHub, opts map[string]any) *Enricher {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	e, err := New(plugin.MapConfig(opts), nil, srv.URL)
	require.NoError(t, err)
	return e
}

func action(name, version string) *model.Package {
	return &model.Package{ID: model.MustPackageVersion(model.EcosystemGitHubActions, name, version)}
}

func TestEnrich(t *testing.T) {
	cases := []struct {
		name string
		sha  string
		want *model.ActionCommit
	}{
		{"a tag points to the commit", tagged, &model.ActionCommit{Reachable: true, Tags: []string{"v1", "v1.0.0"}, Ref: "v1"}},
		{"the head of the default branch", headSHA, &model.ActionCommit{Reachable: true, Ref: "main"}},
		{"behind the default branch", onMain, &model.ActionCommit{Reachable: true, Ref: "main"}},
		{"behind another branch", onBranch, &model.ActionCommit{Reachable: true, Ref: "release"}},
		{"behind a tag", onTag, &model.ActionCommit{Reachable: true, Ref: "v0.9.0"}},
		{"diverged from each ref", impostor, &model.ActionCommit{Reachable: false}},
		{"a commit outside the network", unknown, &model.ActionCommit{Reachable: false}},
		{"an upper-case SHA", strings.ToUpper(onMain), &model.ActionCommit{Reachable: true, Ref: "main"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnricher(t, newFake(), nil)
			p := action("o/r", tc.sha)
			require.NoError(t, e.Enrich(context.Background(), []*model.Package{p}))
			require.NotNil(t, p.Action)
			assert.Equal(t, tc.want.Reachable, p.Action.Reachable)
			assert.ElementsMatch(t, tc.want.Tags, p.Action.Tags)
			if len(tc.want.Tags) < 2 {
				assert.Equal(t, tc.want.Ref, p.Action.Ref)
			}
		})
	}
}

func TestEnrichSkipsOtherPackages(t *testing.T) {
	f := newFake()
	e := newEnricher(t, f, nil)
	pkgs := []*model.Package{
		action("o/r", "v1"),
		{ID: model.MustPackageVersion(model.EcosystemNpm, "lodash", "4.17.21")},
	}
	require.NoError(t, e.Enrich(context.Background(), pkgs))
	for _, p := range pkgs {
		assert.Nil(t, p.Action)
	}
	assert.Empty(t, f.calls, "a tag pin and another ecosystem make no call")
}

func TestEnrichListsTagsOncePerRepository(t *testing.T) {
	f := newFake()
	e := newEnricher(t, f, nil)
	require.NoError(t, e.Enrich(context.Background(), []*model.Package{action("o/r", tagged)}))
	require.NoError(t, e.Enrich(context.Background(), []*model.Package{action("O/R", tagged)}))
	assert.Equal(t, 1, f.calls["tags"])
}

func TestEnrichFailsOpen(t *testing.T) {
	cases := []struct {
		name      string
		opts      map[string]any
		rateLimit bool
		pkg       *model.Package
		wantMsg   []string
	}{
		{
			name: "the budget runs out", opts: map[string]any{"max_calls": 3}, pkg: action("o/r", impostor),
			wantMsg: []string{"budget of 3 GitHub API calls ran out for o/r", "plugins.actionrefs.options.max_calls"},
		},
		{
			name: "a rate limit", rateLimit: true, pkg: action("o/r", impostor),
			wantMsg: []string{"GitHub API rate limit for o/r", "Set GITHUB_TOKEN or run gh auth login", "plugins.actionrefs.enabled to false"},
		},
		{
			name: "no such repository", pkg: action("o/missing", impostor),
			wantMsg: []string{"answered 404", "o/missing"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.rateLimit = tc.rateLimit
			e := newEnricher(t, f, tc.opts)
			err := e.Enrich(context.Background(), []*model.Package{tc.pkg})
			assert.Nil(t, tc.pkg.Action, "vet never reports an impostor from a partial check")
			require.ErrorIs(t, err, plugin.ErrUnavailable)
			var u plugin.UnavailableError
			require.True(t, errors.As(err, &u))
			for _, want := range tc.wantMsg {
				assert.Contains(t, string(u), want)
			}
		})
	}
}

func TestEnrichStopsAfterARateLimit(t *testing.T) {
	f := newFake()
	f.rateLimit = true
	e := newEnricher(t, f, nil)
	pkgs := []*model.Package{action("o/r", impostor), action("o/other", impostor)}
	err := e.Enrich(context.Background(), pkgs)
	require.ErrorIs(t, err, plugin.ErrUnavailable)
	assert.Contains(t, err.Error(), "o/r, o/other")
	total := 0
	for _, n := range f.calls {
		total += n
	}
	assert.Equal(t, 1, total, "the rate limit stops the other calls")
}

func TestNewRejectsABadBudget(t *testing.T) {
	_, err := New(plugin.MapConfig(map[string]any{"max_calls": 0}), nil, "")
	assert.ErrorContains(t, err, "max_calls must be 1 or more")
}
