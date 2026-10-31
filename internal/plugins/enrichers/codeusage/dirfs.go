package codeusage

import (
	"errors"
	"io/fs"
	"slices"
	"sync"
)

// listedFS keeps the listing of each directory that it reads. modgraph lists
// a directory of a module for each import that the module can hold, and the
// sources of a build list do not change during a scan. The other calls go to
// the file system as they are.
type listedFS struct {
	fsys fs.FS

	mu    sync.Mutex
	lists map[string]listing
}

type listing struct {
	entries []fs.DirEntry
	err     error
}

func newListedFS(fsys fs.FS) *listedFS {
	return &listedFS{fsys: fsys, lists: map[string]listing{}}
}

func (l *listedFS) Open(name string) (fs.File, error) { return l.fsys.Open(name) }

func (l *listedFS) Stat(name string) (fs.FileInfo, error) { return fs.Stat(l.fsys, name) }

func (l *listedFS) ReadFile(name string) ([]byte, error) { return fs.ReadFile(l.fsys, name) }

// ReadDir returns a copy of the listing, so a caller can sort it. It keeps
// no other error than fs.ErrNotExist. A shared listing lives for the scan,
// and a kept error such as too many open files would make the module open
// for each later go.mod.
func (l *listedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	l.mu.Lock()
	got, ok := l.lists[name]
	l.mu.Unlock()
	if !ok {
		entries, err := fs.ReadDir(l.fsys, name)
		got = listing{entries: entries, err: err}
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			l.mu.Lock()
			l.lists[name] = got
			l.mu.Unlock()
		}
	}
	return slices.Clone(got.entries), got.err
}
