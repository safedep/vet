package ci

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/ci/githubci"
	"github.com/safedep/vet/v2/internal/gitbase/gitbasetest"
	"github.com/safedep/vet/v2/internal/tui/output"
)

const (
	oldSHA = "1111111111111111111111111111111111111111"
	newSHA = "2222222222222222222222222222222222222222"
)

// githubRepo writes a repository root with a .github directory.
func githubRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".github"), 0o755))
	for rel, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	return dir
}

func TestOpenRepo(t *testing.T) {
	_, err := openRepo(t.TempDir())
	assert.Equal(t, app.ExitUsage, app.ExitCode(err), "a directory that is not on GitHub")
	assert.ErrorContains(t, err, "vet ci knows only GitHub")

	git := gitbasetest.Repo(t, map[string]string{".github/x": "x", "sub/.github/x": "x"})
	_, err = openRepo(filepath.Join(git, "sub"))
	assert.Equal(t, app.ExitUsage, app.ExitCode(err), "a directory below the root of a repository")
	assert.ErrorContains(t, err, "is not the root of its git repository")

	repo, err := openRepo(git)
	require.NoError(t, err)
	repo.close()
}

func TestWrite(t *testing.T) {
	dir := githubRepo(t, map[string]string{".github/dependabot.yml": "old"})
	require.NoError(t, os.Chmod(filepath.Join(dir, ".github", "dependabot.yml"), 0o600))
	repo, err := openRepo(dir)
	require.NoError(t, err)
	t.Cleanup(repo.close)

	require.NoError(t, repo.write([]change{
		{path: ".github/workflows/vet.yml", after: []byte("new")},
		{path: ".github/dependabot.yml", before: []byte("old"), after: []byte("old\nmore")},
	}))
	got, err := repo.read(".github/workflows/vet.yml")
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, ".github", "dependabot.yml"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "a file keeps its mode")
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".github"))
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".tmp"), "no temporary file stays")
	}

	missing, err := repo.read(".github/none.yml")
	require.NoError(t, err)
	assert.Nil(t, missing)
}

func TestWriteRefusesASymbolicLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs symbolic links")
	}
	outside := filepath.Join(t.TempDir(), "target.yml")
	dir := githubRepo(t, nil)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o755))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, ".github", "workflows", "vet.yml")))
	repo, err := openRepo(dir)
	require.NoError(t, err)
	t.Cleanup(repo.close)

	err = repo.write([]change{{path: ".github/workflows/vet.yml", after: []byte("x")}})
	assert.ErrorContains(t, err, "symbolic link")
	assert.NoFileExists(t, outside)
}

func TestFirst(t *testing.T) {
	dir := githubRepo(t, map[string]string{".github/dependabot.yaml": "x"})
	repo, err := openRepo(dir)
	require.NoError(t, err)
	t.Cleanup(repo.close)

	name, data, err := repo.first(githubci.DependabotPaths)
	require.NoError(t, err)
	assert.Equal(t, ".github/dependabot.yaml", name, "the name that exists")
	assert.Equal(t, "x", string(data))

	name, data, err = repo.first(githubci.WorkflowPaths)
	require.NoError(t, err)
	assert.Equal(t, githubci.WorkflowPaths[0], name, "the first name when none exists")
	assert.Nil(t, data)
}

func TestDependabotChange(t *testing.T) {
	const entry = "version: 2\nupdates:\n  - package-ecosystem: gomod\n    directory: /\n"
	cases := []struct {
		name     string
		files    map[string]string
		wantPath string
	}{
		{name: "no config", wantPath: ".github/dependabot.yml"},
		{name: "a yaml config", files: map[string]string{".github/dependabot.yaml": entry}, wantPath: ".github/dependabot.yaml"},
		{name: "an entry for the actions", files: map[string]string{".github/dependabot.yml": "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n"}},
		{name: "a config that vet cannot extend", files: map[string]string{".github/dependabot.yml": "version: 2\nupdates: []\n"}},
		{name: "Renovate", files: map[string]string{"renovate.json": "{}"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, err := openRepo(githubRepo(t, tc.files))
			require.NoError(t, err)
			t.Cleanup(repo.close)
			c, err := dependabotChange(repo)
			require.NoError(t, err)
			if tc.wantPath == "" {
				assert.Nil(t, c)
				return
			}
			require.NotNil(t, c)
			assert.Equal(t, tc.wantPath, c.path)
			assert.Contains(t, string(c.after), "package-ecosystem: github-actions")
		})
	}
}

func TestGithubError(t *testing.T) {
	err := githubError(fmt.Errorf("actions/checkout: %w the cooldown of 24 hours", githubci.ErrNoRelease))
	assert.Equal(t, app.ExitRuntime, app.ExitCode(err))
	assert.Contains(t, fmt.Sprintf("%+v", err), "cooldown")
}

// fakeGitHub serves the releases and the tag commits of safedep/vet and
// actions/checkout.
func fakeGitHub(t *testing.T) string {
	t.Helper()
	old := time.Now().Add(-72 * time.Hour).UTC().Format(time.RFC3339)
	releases := map[string]string{
		"safedep/vet":      `[{"tag_name": "v2.0.0-alpha.20261002000000", "prerelease": true, "immutable": true, "published_at": "` + old + `"}, {"tag_name": "v2.0.0-alpha.20261001000000", "prerelease": true, "immutable": true, "published_at": "` + old + `"}]`,
		"actions/checkout": `[{"tag_name": "v6.0.2", "published_at": "` + old + `"}, {"tag_name": "v6.0.1", "published_at": "` + old + `"}]`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/repos/")
		if repo, ok := strings.CutSuffix(path, "/releases"); ok {
			if page := r.URL.Query().Get("page"); page != "" && page != "0" && page != "1" {
				_, err := w.Write([]byte("[]"))
				assert.NoError(t, err)
				return
			}
			_, err := w.Write([]byte(releases[repo]))
			assert.NoError(t, err)
			return
		}
		if strings.Contains(path, "/commits/") {
			_, err := w.Write([]byte(newSHA))
			assert.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// runCI runs a vet ci command with the GitHub API at apiURL, and returns
// its stdout.
func runCI(t *testing.T, apiURL string, args ...string) (string, error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	env := map[string]string{"VET_GITHUB_API_URL": apiURL}
	a := app.New(app.Options{
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Environ:   func() []string { return []string{"VET_GITHUB_API_URL=" + apiURL} },
	})
	var stdout, stderr bytes.Buffer
	output.SetWriters(&stdout, &stderr)
	t.Cleanup(func() { output.SetWriters(os.Stdout, os.Stderr) })
	cmd := New(a)
	cmd.SetArgs(args)
	cmd.SetOut(&stderr)
	cmd.SetErr(&stderr)
	err := cmd.ExecuteContext(context.Background())
	return stdout.String(), err
}

const pinned = `name: vet
on:
  pull_request:
jobs:
  vet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@` + oldSHA + ` # v6.0.1
      - uses: safedep/vet@` + oldSHA + ` # v2.0.0-alpha.20261001000000
`

func TestUpdate(t *testing.T) {
	api := fakeGitHub(t)
	dir := githubRepo(t, map[string]string{".github/workflows/vet.yml": pinned})

	out, err := runCI(t, api, "update", dir, "--dry-run")
	require.NoError(t, err)
	assert.Contains(t, out, "+      - uses: safedep/vet@"+newSHA+" # v2.0.0-alpha.20261002000000")
	got, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "vet.yml"))
	require.NoError(t, err)
	assert.Equal(t, pinned, string(got), "a dry run writes nothing")

	_, err = runCI(t, api, "update", dir)
	require.NoError(t, err)
	got, err = os.ReadFile(filepath.Join(dir, ".github", "workflows", "vet.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(got), "safedep/vet@"+newSHA+" # v2.0.0-alpha.20261002000000\n")
	assert.Contains(t, string(got), "actions/checkout@"+newSHA+" # v6.0.2\n")
}

func TestUpdateFails(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{name: "no workflow", want: "has no vet workflow"},
		{name: "not YAML", files: map[string]string{".github/workflows/vet.yml": "jobs: [\n"}, want: "is not valid YAML"},
		{name: "no vet pin", files: map[string]string{".github/workflows/vet.yml": "jobs: {}\n"}, want: "has no safedep/vet action pinned"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runCI(t, "http://127.0.0.1:1", "update", githubRepo(t, tc.files))
			assert.Equal(t, app.ExitUsage, app.ExitCode(err))
			assert.ErrorContains(t, err, tc.want)
		})
	}
}

// A test build has no release, and init says so before it calls the
// network.
func TestInitNeedsARelease(t *testing.T) {
	_, err := runCI(t, "http://127.0.0.1:1", "init", githubRepo(t, nil))
	assert.Equal(t, app.ExitUsage, app.ExitCode(err))
	assert.ErrorContains(t, err, "development build")
}
