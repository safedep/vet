package extractors

import (
	"fmt"
	"path/filepath"
	"strings"
)

// MaxLinkedDirs bounds the linked folders that one walk enters. Folders
// that link to each other under several names would make the walk grow at
// each level.
const MaxLinkedDirs = 64

// ErrTooManyLinks tells that a walk reached MaxLinkedDirs. The walk goes on
// without the folder.
var ErrTooManyLinks = fmt.Errorf("the walk follows at most %d linked folders", MaxLinkedDirs)

// Links holds the linked folders that one walk is inside. A walk enters a
// second link to a folder that it already left, under the name of that
// link: .claude and .vscode can point at one folder, and each name gives
// its files a different kind. A walk does not enter a folder that it is
// inside, so a link cannot make a loop.
type Links struct {
	open     map[string]bool
	followed int
}

// Follow runs walk for the linked folder whose real path is target. from is
// the real path of the folder that holds the link. Follow does not run walk
// when the target holds the link or the walk is inside the target. It
// returns ErrTooManyLinks when the walk reached MaxLinkedDirs.
func (l *Links) Follow(from, target string, walk func() error) error {
	if within(from, target) || l.open[target] {
		return nil
	}
	if l.followed >= MaxLinkedDirs {
		return ErrTooManyLinks
	}
	l.followed++
	if l.open == nil {
		l.open = map[string]bool{}
	}
	l.open[target] = true
	defer delete(l.open, target)
	return walk()
}

// within reports whether path is dir or a path under it.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
