package sources

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/plugins/sources/git"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func TestDetect(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "bom.json")
	tarFile := filepath.Join(root, "img.tar")
	require.NoError(t, os.WriteFile(file, []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(tarFile, nil, 0o600))

	cases := []struct {
		target, want string
		usage        bool
	}{
		{"pkg:npm/lodash@4.17.21", "purl", false},
		{"oci://alpine:3.20", "image", false},
		{"https://github.com/safedep/vet", "git", false},
		{"git@github.com:safedep/vet.git", "git", false},
		{root, "dir", false},
		{file, "sbom", false},
		{tarFile, "image", false},
		{filepath.Join(root, "missing"), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			got, err := Detect(tc.target)
			if tc.usage {
				assert.Equal(t, app.ExitUsage, app.ExitCode(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDirSource(t *testing.T) {
	root := t.TempDir()
	real, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	targets := []string{root}
	// Windows needs a privilege to create a symbolic link.
	if link := filepath.Join(t.TempDir(), "link"); os.Symlink(root, link) == nil {
		targets = append(targets, link)
	}

	for _, target := range targets {
		s, err := New(target, Options{})
		require.NoError(t, err)
		as := plugintest.TestSource(t, s)
		require.Len(t, as, 1)
		assert.Equal(t, plugin.ArtifactDirectory, as[0].Kind)
		assert.Equal(t, real, as[0].Key, "one key for each spelling of a directory")
		assert.Equal(t, target, as[0].Label)
	}
}

func TestPURLSource(t *testing.T) {
	s, err := New("pkg:npm/%40babel/core@7.24.0", Options{})
	require.NoError(t, err)
	as := plugintest.TestSource(t, s)
	assert.Equal(t, "purl:pkg:npm/%40babel/core@7.24.0", as[0].Key)

	s, err = New("pkg:nope/x@1", Options{})
	require.NoError(t, err)
	for _, err := range s.Artifacts(context.Background()) {
		assert.Error(t, err)
	}
}

func TestSBOMSource(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "app.cdx.json")
	require.NoError(t, os.WriteFile(file, []byte("{}"), 0o600))
	s, err := New(file, Options{})
	require.NoError(t, err)
	as := plugintest.TestSource(t, s)
	assert.Equal(t, plugin.ArtifactSBOM, as[0].Kind)
	assert.Equal(t, []string{"app.cdx.json"}, as[0].Include)
}

func TestGitSource(t *testing.T) {
	repoDir := t.TempDir()
	repo, err := gogit.PlainInit(repoDir, false)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "go.mod"), []byte("module example.com/x\n"), 0o600))
	wt, err := repo.Worktree()
	require.NoError(t, err)
	_, err = wt.Add("go.mod")
	require.NoError(t, err)
	sig := &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()}
	head, err := wt.Commit("init", &gogit.CommitOptions{Author: sig})
	require.NoError(t, err)
	_, err = repo.CreateTag("v1", head, nil)
	require.NoError(t, err)

	for _, target := range []string{"file://" + repoDir, "file://" + repoDir + "#v1"} {
		t.Run(target, func(t *testing.T) {
			s, err := New(target, Options{})
			require.NoError(t, err)
			as := plugintest.TestSource(t, s)
			require.Len(t, as, 1)
			a := as[0]
			assert.FileExists(t, filepath.Join(a.Path, "go.mod"))
			require.NotNil(t, a.Close)
			require.NoError(t, a.Close())
			assert.NoDirExists(t, a.Path)
		})
	}
}

func TestGitKey(t *testing.T) {
	cases := map[string]string{
		"https://github.com/safedep/vet":      "git:github.com/safedep/vet",
		"https://GitHub.com/safedep/vet.git/": "git:github.com/safedep/vet",
		"git@github.com:safedep/vet.git":      "git:github.com/safedep/vet",
		"ssh://git@gitlab.com/a/b.git":        "git:gitlab.com/a/b",
	}
	for in, want := range cases {
		got, err := git.Key(in)
		require.NoError(t, err)
		assert.Equal(t, want, got, in)
	}
}

func TestImageTarballSource(t *testing.T) {
	img, err := random.Image(256, 1)
	require.NoError(t, err)
	ref, err := name.ParseReference("example.com/test:1")
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "img.tar")
	require.NoError(t, tarball.WriteToFile(file, ref, img))

	s, err := New(file, Options{})
	require.NoError(t, err)
	as := plugintest.TestSource(t, s)
	require.Len(t, as, 1)
	assert.Equal(t, plugin.ArtifactImage, as[0].Kind)
	assert.NotNil(t, as[0].Root)
	require.NoError(t, as[0].Close())
}

func TestRegister(t *testing.T) {
	Register(Options{})
	t.Cleanup(func() {
		for _, n := range []string{"dir", "git", "image", "sbom", "purl"} {
			plugin.Unregister(plugin.KindSource, n)
		}
	})
	s, err := plugin.NewSource("dir", plugin.MapConfig{"target": t.TempDir()})
	require.NoError(t, err)
	plugintest.TestSource(t, s)

	_, err = plugin.NewSource("dir", plugin.MapConfig{})
	assert.Error(t, err)
}
