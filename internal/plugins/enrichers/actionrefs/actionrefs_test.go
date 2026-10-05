package actionrefs

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/github"
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
	release  = "9999999999999999999999999999999999999999"
	orphan   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// fakeGitHub serves the GitHub API calls of the enricher for the
// repository o/r. compare maps base...head to a status. A missing pair is
// diverged, a base of orphan is a 404, and a head of unknown is a commit
// that the network does not have. A pageSize above 0 pages the lists.
type fakeGitHub struct {
	mu        sync.Mutex
	calls     map[string]int
	tags      map[string]string
	branches  map[string]string
	compare   map[string]string
	pageSize  int
	rateLimit bool
}

func newFake() *fakeGitHub {
	return &fakeGitHub{
		calls:    map[string]int{},
		tags:     map[string]string{"v1.0.0": tagged, "v1": tagged, "v0.9.0": oldTag},
		branches: map[string]string{"main": headSHA, "release": release, "gh-pages": orphan},
		compare: map[string]string{
			headSHA + "..." + onMain: "behind", release + "..." + onBranch: "behind", oldTag + "..." + onTag: "behind",
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
	if !strings.HasPrefix(r.URL.Path, "/repos/o/r/") && r.URL.Path != "/repos/o/r" {
		http.NotFound(w, r)
		return
	}
	switch {
	case path == "":
		writeJSON(w, map[string]string{"default_branch": "main"})
	case path == "/tags":
		f.writePage(w, r, f.tags)
	case path == "/branches":
		f.writePage(w, r, f.branches)
	case strings.HasPrefix(path, "/commits/"):
		if strings.HasSuffix(path, unknown) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			writeJSON(w, map[string]string{"message": "No commit found for SHA"})
			return
		}
		_, err := w.Write([]byte(strings.TrimPrefix(path, "/commits/")))
		if err != nil {
			panic(err)
		}
	case strings.HasPrefix(path, "/compare/"):
		pair := strings.TrimPrefix(path, "/compare/")
		if strings.HasPrefix(pair, orphan) {
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

// writePage writes one page of refs in name order, with a Link header to
// the next page.
func (f *fakeGitHub) writePage(w http.ResponseWriter, r *http.Request, m map[string]string) {
	all := []map[string]any{}
	for _, name := range slices.Sorted(maps.Keys(m)) {
		all = append(all, map[string]any{"name": name, "commit": map[string]string{"sha": m[name]}})
	}
	if f.pageSize > 0 {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = max(page, 1)
		start, end := (page-1)*f.pageSize, page*f.pageSize
		if end < len(all) {
			w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?page=%d>; rel="next"`, r.Host, r.URL.Path, page+1))
		}
		all = all[min(start, len(all)):min(end, len(all))]
	}
	writeJSON(w, all)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}

func (f *fakeGitHub) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		n += c
	}
	return n
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
		{"the head of another branch", release, &model.ActionCommit{Reachable: true, Ref: "release"}},
		{"behind the default branch", onMain, &model.ActionCommit{Reachable: true, Ref: "main"}},
		{"behind a branch after an orphan branch", onBranch, &model.ActionCommit{Reachable: true, Ref: "release"}},
		{"behind a tag", onTag, &model.ActionCommit{Reachable: true, Ref: "v0.9.0"}},
		{"diverged from each ref", impostor, &model.ActionCommit{Reachable: false}},
		{"a commit outside the network", unknown, &model.ActionCommit{Reachable: false}},
		{"an upper-case SHA", strings.ToUpper(onMain), &model.ActionCommit{Reachable: true, Ref: "main"}},
	}
	for _, tc := range cases {
		for _, pageSize := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s, page size %d", tc.name, pageSize), func(t *testing.T) {
				f := newFake()
				f.pageSize = pageSize
				e := newEnricher(t, f, nil)
				p := action("o/r", tc.sha)
				require.NoError(t, e.Enrich(context.Background(), []*model.Package{p}))
				assert.Equal(t, tc.want, p.Action)
			})
		}
	}
}

func TestEnrichComparesEachCommitOnce(t *testing.T) {
	f := newFake()
	for i := range 200 {
		f.tags[fmt.Sprintf("v0.%d.0", i)] = oldTag
	}
	e := newEnricher(t, f, nil)
	p := action("o/r", impostor)
	require.NoError(t, e.Enrich(context.Background(), []*model.Package{p}))
	assert.Equal(t, &model.ActionCommit{Reachable: false}, p.Action)
	assert.Equal(t, 5, f.calls["compare"], "one compare for each distinct commit of the refs")
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
	assert.Zero(t, f.total(), "a tag pin and another ecosystem make no call")
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
		pkgs      []*model.Package
		wantMsg   []string
		wantCalls int
	}{
		{
			name: "the budget runs out", opts: map[string]any{"max_calls": 3}, pkgs: []*model.Package{action("o/r", impostor)},
			wantMsg:   []string{"The check of o/r stopped with this reason: the budget of 3 GitHub API calls ran out.", "plugins.actionrefs.options.max_calls"},
			wantCalls: 3,
		},
		{
			name: "a rate limit stops the other calls", rateLimit: true,
			pkgs:      []*model.Package{action("o/r", impostor), action("o/other", impostor)},
			wantMsg:   []string{"The check of o/r, o/other stopped with this reason: GitHub API rate limit.", "Set GITHUB_TOKEN or run gh auth login", "plugins.actionrefs.enabled to false"},
			wantCalls: 1,
		},
		{
			name: "no such repository", pkgs: []*model.Package{action("o/missing", impostor), action("o/missing", tagged)},
			wantMsg: []string{"answered 404", "o/missing"}, wantCalls: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.rateLimit = tc.rateLimit
			e := newEnricher(t, f, tc.opts)
			err := e.Enrich(context.Background(), tc.pkgs)
			for _, p := range tc.pkgs {
				assert.Nil(t, p.Action, "vet never reports an impostor from a partial check")
			}
			var u plugin.UnavailableError
			require.ErrorAs(t, err, &u)
			assert.ErrorIs(t, err, plugin.ErrUnavailable)
			for _, want := range tc.wantMsg {
				assert.Contains(t, string(u), want)
			}
			assert.Equal(t, tc.wantCalls, f.total())
		})
	}
}

func TestEnrichAnswersATagAfterTheBudgetRunsOut(t *testing.T) {
	e := newEnricher(t, newFake(), map[string]any{"max_calls": 4})
	spent, pinned := action("o/r", impostor), action("o/r", tagged)
	err := e.Enrich(context.Background(), []*model.Package{spent, pinned})
	assert.ErrorIs(t, err, plugin.ErrUnavailable)
	assert.Nil(t, spent.Action)
	assert.Equal(t, &model.ActionCommit{Reachable: true, Tags: []string{"v1", "v1.0.0"}, Ref: "v1"}, pinned.Action)
}

func TestDefaultBudget(t *testing.T) {
	cases := []struct {
		name   string
		tokens github.TokenProvider
		want   int
	}{
		{"no token", nil, anonymousMaxCalls},
		{"a token", github.EnvProvider{LookupEnv: func(string) (string, bool) { return "t", true }}, tokenMaxCalls},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(newFake())
			t.Cleanup(srv.Close)
			e, err := New(plugin.MapConfig(nil), tc.tokens, srv.URL)
			require.NoError(t, err)
			require.NoError(t, e.Enrich(context.Background(), []*model.Package{action("o/r", tagged)}))
			assert.Equal(t, tc.want, e.maxCalls)
		})
	}
}

func TestNewRejectsABadBudget(t *testing.T) {
	_, err := New(plugin.MapConfig(map[string]any{"max_calls": 0}), nil, "")
	assert.ErrorContains(t, err, "max_calls must be 1 or more")
}
