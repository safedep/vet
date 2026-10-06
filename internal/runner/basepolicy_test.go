package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/gitbase/gitbasetest"
)

// resolver maps a policy name to <configDir>/<name>.yml, and keeps a path.
type resolver struct{ configDir string }

func (r resolver) ResolvePolicy(v string) string {
	if _, err := os.Stat(v); err == nil || filepath.Ext(v) != "" {
		return v
	}
	return r.PolicyFile(v)
}

func (r resolver) PolicyFile(name string) string { return filepath.Join(r.configDir, name+".yml") }

const strict = "version: 2\nrules: []\n"

func TestPolicySource(t *testing.T) {
	cases := []struct {
		name        string
		base        map[string]string
		head        map[string]string
		target      string // relative to the repository
		policy      string // relative to the repository, or a name
		baseRef     string
		wantNil     bool
		wantDocs    map[string]string
		wantChanged bool
	}{
		{
			name: "no base ref reads the disk", base: map[string]string{"p.yml": strict}, head: map[string]string{"p.yml": "head\n"},
			policy: "p.yml", wantDocs: map[string]string{"p.yml": "head\n"},
		},
		{
			name: "unchanged", base: map[string]string{"p.yml": strict}, policy: "p.yml", baseRef: "HEAD",
			wantDocs: map[string]string{"HEAD:p.yml": strict},
		},
		{
			name: "CRLF checkout", base: map[string]string{"p.yml": strict}, head: map[string]string{"p.yml": "version: 2\r\nrules: []\r\n"},
			policy: "p.yml", baseRef: "HEAD", wantDocs: map[string]string{"HEAD:p.yml": strict},
		},
		{
			name: "edited", base: map[string]string{"p.yml": strict}, head: map[string]string{"p.yml": "loose\n"},
			policy: "p.yml", baseRef: "HEAD", wantDocs: map[string]string{"HEAD:p.yml": strict}, wantChanged: true,
		},
		{
			name: "deleted by the change", base: map[string]string{"p.yml": strict}, head: map[string]string{"p.yml": ""},
			policy: "p.yml", baseRef: "HEAD", wantDocs: map[string]string{"HEAD:p.yml": strict}, wantChanged: true,
		},
		{
			name: "added by the change", base: map[string]string{"a.txt": "x"}, head: map[string]string{"p.yml": strict},
			policy: "p.yml", baseRef: "HEAD", wantNil: true, wantChanged: true,
		},
		{
			name: "monorepo target", base: map[string]string{".github/vet/policy.yml": strict, "svc/api/package.json": "{}"},
			head: map[string]string{".github/vet/policy.yml": "loose\n"}, target: "svc/api", policy: ".github/vet/policy.yml", baseRef: "HEAD",
			wantDocs: map[string]string{"HEAD:.github/vet/policy.yml": strict}, wantChanged: true,
		},
		{
			name: "directory gets a new file", base: map[string]string{"policies/a.yml": strict},
			head: map[string]string{"policies/b.yml": "loose\n"}, policy: "policies", baseRef: "HEAD",
			wantDocs: map[string]string{"HEAD:policies/a.yml": strict}, wantChanged: true,
		},
		{
			name: "no policy at the base and in the change", base: map[string]string{"a.txt": "x"},
			policy: ".github/vet/policy.yml", baseRef: "HEAD", wantNil: true,
		},
		{
			name: "the change deletes the policy directory", base: map[string]string{".github/vet/policy.yml": strict, "a.txt": "x"},
			head: map[string]string{".github/vet/policy.yml": ""}, policy: ".github/vet/policy.yml", baseRef: "HEAD",
			wantDocs: map[string]string{"HEAD:.github/vet/policy.yml": strict}, wantChanged: true,
		},
		{
			name: "a file of the change cannot take over a name", base: map[string]string{"a.txt": "x"},
			head: map[string]string{"strict": "loose\n"}, policy: "strict", baseRef: "HEAD",
			wantDocs: map[string]string{"config": strict},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := gitbasetest.Repo(t, tc.base)
			for rel, content := range tc.head {
				if content == "" {
					require.NoError(t, os.Remove(filepath.Join(repo, rel)))
					if dir := filepath.Dir(rel); dir != "." {
						require.NoError(t, os.RemoveAll(filepath.Join(repo, dir)))
					}
					continue
				}
				gitbasetest.Write(t, repo, rel, content)
			}
			configDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(configDir, "strict.yml"), []byte(strict), 0o600))
			t.Chdir(repo)
			target := filepath.Join(repo, tc.target)

			src, changed, err := policySource(context.Background(), target, tc.baseRef, tc.policy, resolver{configDir: configDir})
			require.NoError(t, err)
			assert.Equal(t, tc.wantChanged, changed)
			if tc.wantNil {
				assert.Nil(t, src)
				return
			}
			require.NotNil(t, src)
			docs, err := src.Policies(context.Background())
			require.NoError(t, err)
			got := map[string]string{}
			for _, d := range docs {
				name := d.Name
				if filepath.IsAbs(name) {
					name = "config"
				}
				got[name] = string(d.Content)
			}
			assert.Equal(t, tc.wantDocs, got)
		})
	}
}

func TestPolicySourceFailsClosed(t *testing.T) {
	repo := gitbasetest.Repo(t, map[string]string{"p.yml": strict})
	t.Chdir(repo)
	ctx := context.Background()

	_, _, err := policySource(ctx, repo, "no-such-ref", "p.yml", resolver{})
	assert.Equal(t, app.ExitUsage, app.ExitCode(err), "an unknown base ref is a usage error")

	_, _, err = policySource(ctx, filepath.Join(repo, "p.yml"), "HEAD", "p.yml", resolver{})
	assert.Equal(t, app.ExitUsage, app.ExitCode(err), "a target that is not a directory is a usage error")

	_, _, err = policySource(ctx, t.TempDir(), "HEAD", "p.yml", resolver{})
	assert.Equal(t, app.ExitUsage, app.ExitCode(err), "a directory outside git is a usage error")
}

func TestPolicySourceRefusesASymlinkAtTheBase(t *testing.T) {
	repo := gitbasetest.Repo(t, map[string]string{"real.yml": strict})
	require.NoError(t, os.Symlink("real.yml", filepath.Join(repo, "p.yml")))
	gitbasetest.Commit(t, repo)
	t.Chdir(repo)

	_, _, err := policySource(context.Background(), repo, "HEAD", "p.yml", resolver{})
	assert.Equal(t, app.ExitUsage, app.ExitCode(err))
	assert.ErrorContains(t, err, "p.yml")
}

func TestPolicySourceWithNoFile(t *testing.T) {
	src, changed, err := policySource(context.Background(), t.TempDir(), "HEAD", "", resolver{})
	require.NoError(t, err)
	assert.Nil(t, src)
	assert.False(t, changed)
}

// A change cannot move the policy to a path that the base does not have
// with a link in the working tree.
func TestPolicySourceRefusesALinkOfTheChange(t *testing.T) {
	repo := gitbasetest.Repo(t, map[string]string{".github/vet/policy.yml": strict})
	require.NoError(t, os.RemoveAll(filepath.Join(repo, ".github", "vet")))
	gitbasetest.Write(t, repo, "elsewhere/policy.yml", "loose\n")
	require.NoError(t, os.Symlink(filepath.Join("..", "elsewhere"), filepath.Join(repo, ".github", "vet")))
	t.Chdir(repo)

	_, _, err := policySource(context.Background(), repo, "HEAD", ".github/vet/policy.yml", resolver{})
	assert.Equal(t, app.ExitUsage, app.ExitCode(err))
	assert.ErrorContains(t, err, "symbolic link")
}

// A link above the working tree, such as /var on macOS, resolves.
func TestPolicySourceThroughALinkToTheRepository(t *testing.T) {
	repo := gitbasetest.Repo(t, map[string]string{"p.yml": strict})
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(repo, link))
	t.Chdir(link)

	src, changed, err := policySource(context.Background(), link, "HEAD", "p.yml", resolver{})
	require.NoError(t, err)
	assert.False(t, changed)
	docs, err := src.Policies(context.Background())
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Equal(t, "HEAD:p.yml", docs[0].Name)
}
