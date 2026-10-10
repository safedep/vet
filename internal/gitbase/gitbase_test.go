package gitbase

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/gitbase/gitbasetest"
)

func TestOpenAndWalk(t *testing.T) {
	dir := gitbasetest.Repo(t, map[string]string{"app/main.py": "import os\n", "app/lib/util.py": "x = 1\n", "README.md": "x\n"})

	tree, err := Open(filepath.Join(dir, "app"), "HEAD")
	require.NoError(t, err)
	assert.False(t, tree.Commit.IsZero())

	t.Chdir(filepath.Join(dir, "app"))
	_, err = Open(".", "HEAD")
	require.NoError(t, err, "a relative directory works")

	var files []string
	require.NoError(t, tree.Walk(context.Background(), func(rel string, _ *object.File) error {
		files = append(files, rel)
		return nil
	}))
	assert.ElementsMatch(t, []string{"main.py", "lib/util.py"}, files, "paths are relative to the directory")
}

func TestOpenErrors(t *testing.T) {
	_, err := Open(t.TempDir(), "HEAD")
	assert.ErrorIs(t, err, ErrNotRepository)

	dir := gitbasetest.Repo(t, map[string]string{"a.txt": "a"})
	_, err = Open(dir, "no-such-branch")
	assert.ErrorIs(t, err, ErrRevision)
}

func TestWriteBlob(t *testing.T) {
	dir := gitbasetest.Repo(t, map[string]string{"a/b.txt": "base"})
	tree, err := Open(dir, "HEAD")
	require.NoError(t, err)
	out := t.TempDir()
	require.NoError(t, tree.Walk(context.Background(), func(rel string, f *object.File) error {
		return WriteBlob(f, filepath.Join(out, filepath.FromSlash(rel)))
	}))
	same, err := SameBlob(fstest.MapFS{"b.txt": {Data: []byte("base")}}, "b.txt", plumbing.ComputeHash(plumbing.BlobObject, []byte("base")))
	require.NoError(t, err)
	assert.True(t, same)
	assert.FileExists(t, filepath.Join(out, "a", "b.txt"))
}

func TestSameBlobIgnoresCRLF(t *testing.T) {
	lf := []byte("on: push\njobs: {}\n")
	base := plumbing.ComputeHash(plumbing.BlobObject, lf)
	cases := []struct {
		name string
		data string
		want bool
	}{
		{name: "same bytes", data: string(lf), want: true},
		{name: "CRLF checkout of the LF blob", data: "on: push\r\njobs: {}\r\n", want: true},
		{name: "changed", data: "on: pull_request\njobs: {}\n"},
		{name: "changed with CRLF", data: "on: pull_request\r\njobs: {}\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SameBlob(fstest.MapFS{"ci.yml": {Data: []byte(tc.data)}}, "ci.yml", base)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLocalPath(t *testing.T) {
	cases := map[string]bool{
		"go.mod":          true,
		"src/app/main.go": true,
		"../etc/passwd":   false,
		"src/../../x":     false,
		"/etc/passwd":     false,
		"":                false,
		"src/./main.go":   false,
	}
	for rel, want := range cases {
		assert.Equal(t, want, localPath(rel), rel)
	}
}

func TestFS(t *testing.T) {
	dir := gitbasetest.Repo(t, map[string]string{"app/policy.yml": "version: 2\n", "app/lib/util.py": "x = 1\n", "README.md": "x\n"})
	gitbasetest.Write(t, dir, "app/policy.yml", "head\n")

	tree, err := Open(filepath.Join(dir, "app"), "HEAD")
	require.NoError(t, err)
	require.NoError(t, fstest.TestFS(tree.FS(), "policy.yml", "lib/util.py"))

	data, err := fs.ReadFile(tree.FS(), "policy.yml")
	require.NoError(t, err)
	assert.Equal(t, "version: 2\n", string(data), "the FS reads the base, not the head")

	_, err = fs.Stat(tree.FS(), "README.md")
	assert.ErrorIs(t, err, fs.ErrNotExist, "the FS holds only the directory")
}

func TestRepoPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs symbolic links")
	}
	repo := gitbasetest.Repo(t, map[string]string{"a/p.yml": "x", "elsewhere/p.yml": "y"})
	tree, err := Open(repo, "HEAD")
	require.NoError(t, err)

	rel, ok, err := tree.RepoPath(filepath.Join(repo, "a", "p.yml"))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "a/p.yml", rel)

	rel, ok, err = tree.RepoPath(filepath.Join(repo, "gone", "deep", "p.yml"))
	require.NoError(t, err)
	assert.True(t, ok, "a path that the working tree does not have")
	assert.Equal(t, "gone/deep/p.yml", rel)

	_, ok, err = tree.RepoPath(filepath.Join(t.TempDir(), "p.yml"))
	require.NoError(t, err)
	assert.False(t, ok, "a path outside the working tree")

	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(repo, link))
	rel, ok, err = tree.RepoPath(filepath.Join(link, "a", "p.yml"))
	require.NoError(t, err)
	assert.True(t, ok, "a link above the working tree resolves")
	assert.Equal(t, "a/p.yml", rel)

	require.NoError(t, os.Symlink("elsewhere", filepath.Join(repo, "b")))
	_, _, err = tree.RepoPath(filepath.Join(repo, "b", "p.yml"))
	assert.ErrorIs(t, err, ErrLink, "a link in the working tree")
}

func TestSameBlobCountsALinkAsChanged(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.json"), []byte("{}"), 0o600))
	require.NoError(t, os.Symlink("real.json", filepath.Join(dir, "link.json")))
	fsys := os.DirFS(dir)
	for _, base := range []string{"real.json", "{}"} {
		same, err := SameBlob(fsys, "link.json", plumbing.ComputeHash(plumbing.BlobObject, []byte(base)))
		require.NoError(t, err)
		assert.False(t, same, "the target of a link can change with the same link text")
	}
}
