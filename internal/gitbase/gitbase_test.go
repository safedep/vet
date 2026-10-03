package gitbase

import (
	"context"
	"path/filepath"
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
