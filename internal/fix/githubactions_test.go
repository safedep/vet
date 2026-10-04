package fix

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	gh "github.com/google/go-github/v70/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sha = "11bd71901bbe5b1630ceea73d27597364c9af683"

type fakeResolver struct{ calls int }

func (f *fakeResolver) ResolveSHA(_ context.Context, owner, repo, ref string) (string, error) {
	f.calls++
	if owner == "gone" {
		return "", fmt.Errorf("resolve: %w", &gh.ErrorResponse{Response: &http.Response{StatusCode: http.StatusNotFound, Request: &http.Request{Method: "GET", URL: &url.URL{}}}})
	}
	return sha, nil
}

const workflow = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: "actions/setup-go@v5"  # setup
      - uses: actions/checkout@v4
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.19
      - uses: my-org/app/.github/workflows/x.yml@main
      - uses: actions/cache@` + sha + `
      - uses: gone/action@v1
`

const pinned = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@` + sha + ` # v4
      - uses: "actions/setup-go@` + sha + `" # v5; setup
      - uses: actions/checkout@` + sha + ` # v4
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.19
      - uses: my-org/app/.github/workflows/x.yml@main
      - uses: actions/cache@` + sha + `
      - uses: gone/action@v1
`

func project(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for p, content := range map[string]string{
		".github/workflows/ci.yml":                workflow,
		".github/workflows/clean.yml":             "on: push\njobs: {}\n",
		".github/workflows/sub/ignored.yml":       "x: {uses: a/b@v1}\n",
		".github/actions/local/action.yml":        "runs:\n  using: composite\n  steps:\n    - uses: tj-actions/changed-files@v44\n",
		".github/actions/local/notes.yml":         "uses: a/b@v1\n",
		".github/workflows/template.yml.disabled": "uses: a/b@v1\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o640))
	}
	return root
}

func TestPlanAndApply(t *testing.T) {
	root := project(t)
	r := &fakeResolver{}
	p, err := PlanPins(context.Background(), PinOptions{Root: root, Resolver: r, SameRepo: "my-org/app"})
	require.NoError(t, err)

	require.Len(t, p.Files, 2)
	assert.Equal(t, ".github/workflows/ci.yml", p.Files[0].Path)
	assert.Equal(t, ".github/actions/local/action.yml", p.Files[1].Path)
	assert.Equal(t, 4, p.Edits())
	assert.Equal(t, 4, r.calls, "the cache resolves actions/checkout@v4 once")
	require.Len(t, p.Failures, 1)
	assert.Equal(t, "gone/action@v1", p.Failures[0].Action)
	assert.Equal(t, 13, p.Failures[0].Line)
	assert.Equal(t, "GitHub API answered 404 (no such repository or ref)", p.Failures[0].Reason)
	assert.False(t, p.NeedsToken())

	assert.Contains(t, p.Diff(), "@@ -6 +6 @@\n-      - uses: actions/checkout@v4\n+      - uses: actions/checkout@"+sha+" # v4\n")

	before, err := os.ReadFile(filepath.Join(root, ".github/workflows/ci.yml"))
	require.NoError(t, err)
	assert.Equal(t, workflow, string(before), "a plan writes nothing")

	require.NoError(t, p.Apply())
	after, err := os.ReadFile(filepath.Join(root, ".github/workflows/ci.yml"))
	require.NoError(t, err)
	assert.Equal(t, pinned, string(after))
	info, err := os.Stat(filepath.Join(root, ".github/workflows/ci.yml"))
	require.NoError(t, err)
	if info.Mode().Perm() != 0o666 {
		assert.Equal(t, os.FileMode(0o640), info.Mode().Perm(), "the file keeps its mode")
	}

	again, err := PlanPins(context.Background(), PinOptions{Root: root, Resolver: r, SameRepo: "my-org/app"})
	require.NoError(t, err)
	assert.Zero(t, again.Edits(), "a second run has nothing to pin")
}

func TestPlanKeepsCRLF(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ci.yml"), []byte("jobs:\r\n  b:\r\n    steps:\r\n      - uses: a/b@v1\r\n"), 0o644))
	p, err := PlanPins(context.Background(), PinOptions{Root: root, Resolver: &fakeResolver{}, SameRepo: "x/y"})
	require.NoError(t, err)
	require.NoError(t, p.Apply())
	got, err := os.ReadFile(filepath.Join(dir, "ci.yml"))
	require.NoError(t, err)
	assert.Equal(t, "jobs:\r\n  b:\r\n    steps:\r\n      - uses: a/b@"+sha+" # v1\r\n", string(got))
}

func TestGitHubRepo(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/safedep/vet.git": "safedep/vet",
		"git@github.com:safedep/vet.git":     "safedep/vet",
		"ssh://git@github.com/safedep/vet":   "safedep/vet",
		"https://gitlab.com/a/b":             "",
	} {
		assert.Equal(t, want, githubRepo(in), in)
	}
}

func TestPlanWithNoWorkflows(t *testing.T) {
	p, err := PlanPins(context.Background(), PinOptions{Root: t.TempDir(), Resolver: &fakeResolver{}})
	require.NoError(t, err)
	assert.Zero(t, p.Edits())
}
