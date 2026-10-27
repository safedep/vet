package codeusage

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingFS counts the directory listings that reach the file system.
type countingFS struct {
	fstest.MapFS
	lists int
}

func (c *countingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	c.lists++
	return c.MapFS.ReadDir(name)
}

func TestListedFSListsEachDirectoryOnce(t *testing.T) {
	under := &countingFS{MapFS: fstest.MapFS{"x/a.go": {Data: []byte("package x")}, "x/b.go": {Data: []byte("package x")}}}
	l := newListedFS(under)

	first, err := fs.ReadDir(l, "x")
	require.NoError(t, err)
	first[0] = nil
	second, err := fs.ReadDir(l, "x")
	require.NoError(t, err)
	assert.Equal(t, "a.go", second[0].Name(), "each caller gets its own copy of the listing")
	_, err = fs.ReadDir(l, "missing")
	require.Error(t, err)
	_, err = fs.ReadDir(l, "missing")
	require.Error(t, err)
	assert.Equal(t, 2, under.lists)

	data, err := fs.ReadFile(l, "x/a.go")
	require.NoError(t, err)
	assert.Equal(t, "package x", string(data))
	info, err := fs.Stat(l, "x")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}
