// Package gitbase reads the base commit of a git working tree, for pull
// request mode: the files of the base ref under a directory, and whether a
// head file still has the content of its base blob.
package gitbase

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/safedep/dry/log"
)

var (
	// ErrNotRepository reports a directory that is not in a git repository.
	ErrNotRepository = errors.New("not in a git repository")
	// ErrRevision reports a base ref that the repository does not have.
	ErrRevision = errors.New("unknown revision")
	// ErrNotRegular reports a base entry that is a symbolic link or a
	// submodule. vet does not follow it.
	ErrNotRegular = errors.New("not a regular file or directory")
)

// Tree is the tree of the base commit, seen from a directory of the
// working tree.
type Tree struct {
	// Commit is the base commit.
	Commit plumbing.Hash
	tree   *object.Tree
	// prefix is the path of the directory in the repository, with a
	// trailing "/", or "" for the repository root.
	prefix string
	// root is the root of the working tree, with its symbolic links
	// resolved.
	root string
}

// Open resolves rev in the repository of dir.
func Open(dir, rev string) (*Tree, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	repo, err := gogit.PlainOpenWithOptions(dir, &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrNotRepository, dir, err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(wt.Filesystem.Root())
	if err != nil {
		return nil, err
	}
	prefix, err := repoPrefix(root, dir)
	if err != nil {
		return nil, err
	}
	hash, err := repo.ResolveRevision(plumbing.Revision(rev))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrRevision, rev, err)
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, err
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}
	return &Tree{Commit: *hash, tree: tree, prefix: prefix, root: root}, nil
}

// Root returns the root of the working tree, with its symbolic links
// resolved.
func (t *Tree) Root() string { return t.root }

// RepoFS returns the base tree of the whole repository, not only of the
// directory, as a read-only file system.
func (t *Tree) RepoFS() fs.FS {
	return treeFS{t: &Tree{Commit: t.Commit, tree: t.tree, root: t.root}}
}

// RepoPath returns the path of p relative to the root of the working
// tree, in "/" form. It resolves the symbolic links of the directories of
// p. It is false when p is outside the working tree.
func (t *Tree) RepoPath(p string) (string, bool) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(t.root, filepath.Join(dir, filepath.Base(abs)))
	if err != nil || !filepath.IsLocal(rel) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// Walk calls fn with each base file under the directory, with its path
// relative to the directory, in "/" form.
func (t *Tree) Walk(ctx context.Context, fn func(rel string, f *object.File) error) error {
	return t.tree.Files().ForEach(func(f *object.File) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, ok := strings.CutPrefix(f.Name, t.prefix)
		if !ok || rel == "" {
			return nil
		}
		if !localPath(rel) {
			log.Warnf("gitbase: skipped the base file %q, which is not a local path", rel)
			return nil
		}
		return fn(rel, f)
	})
}

// localPath reports whether a tree path stays inside the directory that a
// caller writes it to. go-git rejects ".." in a tree entry today. vet
// checks again, so that no future version of go-git can make a base file
// escape the temporary directory.
func localPath(rel string) bool {
	return fs.ValidPath(rel) && filepath.IsLocal(filepath.FromSlash(rel))
}

// repoPrefix returns the path of dir in the repository, with "/" and a
// trailing "/", or "" for the repository root. root has its symbolic links
// resolved.
func repoPrefix(root, dir string) (string, error) {
	d, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, d)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return "", nil
	}
	return filepath.ToSlash(rel) + "/", nil
}

// WriteBlob writes the content of a base file to dst.
func WriteBlob(f *object.File, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	rd, err := f.Reader()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return errors.Join(err, rd.Close())
	}
	_, err = io.Copy(out, rd)
	return errors.Join(err, out.Close(), rd.Close())
}

// SameBlob reports whether a head file has the content of a base blob.
// Git can check a file out with CRLF line ends and store it with LF
// (core.autocrlf), so the file also matches when its LF form does.
func SameBlob(fsys fs.FS, rel string, base plumbing.Hash) (bool, error) {
	data, err := fs.ReadFile(fsys, rel)
	if err != nil {
		return false, err
	}
	if plumbing.ComputeHash(plumbing.BlobObject, data) == base {
		return true, nil
	}
	lf := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return len(lf) != len(data) && plumbing.ComputeHash(plumbing.BlobObject, lf) == base, nil
}
