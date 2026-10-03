// Package dir is the source of a directory on disk.
package dir

import (
	"context"
	"fmt"
	"iter"
	"os"
	"path/filepath"

	"github.com/safedep/vet/v2/plugin"
)

// Name is the registered name of the source.
const Name = "dir"

// Options configure the source.
type Options struct {
	// Target is the directory as the user typed it.
	Target string `json:"target"`
}

// Source yields one directory artifact.
type Source struct {
	opts Options
}

// New returns the source.
func New(o Options) *Source { return &Source{opts: o} }

// Artifacts yields the directory. The key is the real absolute path, so
// two spellings of one directory share their scan state.
func (s *Source) Artifacts(context.Context) iter.Seq2[plugin.Artifact, error] {
	return func(yield func(plugin.Artifact, error) bool) {
		abs, err := Canonical(s.opts.Target)
		if err != nil {
			yield(plugin.Artifact{}, err)
			return
		}
		yield(plugin.Artifact{
			Kind:  plugin.ArtifactDirectory,
			Root:  os.DirFS(abs),
			Path:  abs,
			Label: s.opts.Target,
			Key:   abs,
		}, nil)
	}
}

// Canonical returns the real absolute path of a directory.
func Canonical(target string) (string, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", target)
	}
	return real, nil
}
