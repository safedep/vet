package gitbase

import (
	"errors"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// FS returns the base tree under the directory as a read-only file system.
// Open fails with ErrNotRegular on a symbolic link or a submodule, and
// ReadDir lists them with their type.
func (t *Tree) FS() fs.FS { return treeFS{t: t} }

type treeFS struct{ t *Tree }

func (f treeFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	full := f.t.prefix + name
	if name == "." {
		full = strings.TrimSuffix(f.t.prefix, "/")
	}
	if full == "" {
		return &treeDir{name: ".", tree: f.t.tree}, nil
	}
	entry, err := f.t.tree.FindEntry(full)
	if errors.Is(err, object.ErrEntryNotFound) || errors.Is(err, object.ErrDirectoryNotFound) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	switch entry.Mode {
	case filemode.Dir:
		sub, err := f.t.tree.Tree(full)
		if err != nil {
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
		return &treeDir{name: path.Base(name), tree: sub}, nil
	case filemode.Regular, filemode.Executable, filemode.Deprecated:
		file, err := f.t.tree.TreeEntryFile(entry)
		if err != nil {
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
		rd, err := file.Reader()
		if err != nil {
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
		return &treeFile{info: info{name: path.Base(name), size: file.Size, mode: 0o444}, rc: rd}, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: ErrNotRegular}
}

type treeFile struct {
	info info
	rc   io.ReadCloser
}

func (f *treeFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *treeFile) Read(b []byte) (int, error) { return f.rc.Read(b) }
func (f *treeFile) Close() error               { return f.rc.Close() }

type treeDir struct {
	name    string
	tree    *object.Tree
	entries []fs.DirEntry
	listed  bool
}

func (d *treeDir) Stat() (fs.FileInfo, error) {
	return info{name: d.name, mode: fs.ModeDir | 0o555}, nil
}

func (d *treeDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errors.New("is a directory")}
}

func (d *treeDir) Close() error { return nil }

// ReadDir returns the entries of the tree in git order, as
// fs.ReadDirFile defines it. A symbolic link and a submodule have the type
// fs.ModeSymlink and fs.ModeIrregular.
func (d *treeDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if !d.listed {
		d.listed = true
		for i := range d.tree.Entries {
			e := &d.tree.Entries[i]
			switch e.Mode {
			case filemode.Dir:
				d.entries = append(d.entries, fs.FileInfoToDirEntry(info{name: e.Name, mode: fs.ModeDir | 0o555}))
			case filemode.Regular, filemode.Executable, filemode.Deprecated:
				file, err := d.tree.TreeEntryFile(e)
				if err != nil {
					return nil, &fs.PathError{Op: "readdir", Path: d.name, Err: err}
				}
				d.entries = append(d.entries, fs.FileInfoToDirEntry(info{name: e.Name, size: file.Size, mode: 0o444}))
			case filemode.Symlink:
				d.entries = append(d.entries, fs.FileInfoToDirEntry(info{name: e.Name, mode: fs.ModeSymlink | 0o444}))
			default:
				d.entries = append(d.entries, fs.FileInfoToDirEntry(info{name: e.Name, mode: fs.ModeIrregular}))
			}
		}
	}
	if n <= 0 {
		out := d.entries
		d.entries = nil
		return out, nil
	}
	if len(d.entries) == 0 {
		return nil, io.EOF
	}
	n = min(n, len(d.entries))
	out := d.entries[:n]
	d.entries = d.entries[n:]
	return out, nil
}

type info struct {
	name string
	size int64
	mode fs.FileMode
}

func (i info) Name() string       { return i.name }
func (i info) Size() int64        { return i.size }
func (i info) Mode() fs.FileMode  { return i.mode }
func (i info) ModTime() time.Time { return time.Time{} }
func (i info) IsDir() bool        { return i.mode.IsDir() }
func (i info) Sys() any           { return nil }
