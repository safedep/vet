// Package manifestmode holds the rules that the manifest extractors share.
// A manifest extractor reads the declared dependencies of a project with
// no lockfile.
package manifestmode

import (
	"errors"
	"io/fs"
	"path"
)

// Locked reports whether one of the lockfiles is in dir or in a parent of
// dir. A workspace keeps one lockfile at its root for every member, so a
// member manifest is locked by the root lockfile.
func Locked(fsys fs.FS, dir string, lockfiles []string) (bool, error) {
	for {
		for _, name := range lockfiles {
			_, err := fs.Stat(fsys, path.Join(dir, name))
			if err == nil {
				return true, nil
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return false, err
			}
		}
		if dir == "." || dir == "/" || dir == "" {
			return false, nil
		}
		dir = path.Dir(dir)
	}
}
