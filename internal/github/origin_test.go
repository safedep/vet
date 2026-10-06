package github

import (
	"path/filepath"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/gitbase/gitbasetest"
)

func TestRemoteRepo(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/safedep/vet.git": "safedep/vet",
		"git@github.com:safedep/vet.git":     "safedep/vet",
		"ssh://git@github.com/safedep/vet":   "safedep/vet",
		"https://gitlab.com/a/b":             "",
	} {
		assert.Equal(t, want, RemoteRepo(in), in)
	}
}

func TestOriginRepo(t *testing.T) {
	dir := gitbasetest.Repo(t, map[string]string{"sub/a.txt": "a"})
	assert.Empty(t, OriginRepo(dir), "a repository with no origin")

	repo, err := gogit.PlainOpen(dir)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{"git@github.com:acme/app.git"}})
	require.NoError(t, err)
	assert.Equal(t, "acme/app", OriginRepo(dir))
	assert.Equal(t, "acme/app", OriginRepo(filepath.Join(dir, "sub")), "a directory in the repository")
	assert.Empty(t, OriginRepo(t.TempDir()), "no repository")

	root, ok := WorktreeRoot(filepath.Join(dir, "sub"))
	require.True(t, ok)
	assert.Equal(t, dir, root)
	_, ok = WorktreeRoot(t.TempDir())
	assert.False(t, ok)
}
