// Package sbom is the source of one SBOM file: CycloneDX or SPDX.
package sbom

import (
	"context"
	"fmt"
	"iter"
	"os"
	"path/filepath"

	"github.com/safedep/vet/v2/plugin"
)

// Name is the registered name of the source.
const Name = "sbom"

// Options configure the source.
type Options struct {
	Target string `json:"target"`
}

// Source yields one SBOM artifact.
type Source struct {
	opts Options
}

// New returns the source.
func New(o Options) *Source { return &Source{opts: o} }

// Artifacts yields the directory of the file, limited to the file. The key
// is the real absolute path of the file.
func (s *Source) Artifacts(context.Context) iter.Seq2[plugin.Artifact, error] {
	return func(yield func(plugin.Artifact, error) bool) {
		abs, err := filepath.Abs(s.opts.Target)
		if err == nil {
			abs, err = filepath.EvalSymlinks(abs)
		}
		if err != nil {
			yield(plugin.Artifact{}, err)
			return
		}
		info, err := os.Stat(abs)
		if err != nil {
			yield(plugin.Artifact{}, err)
			return
		}
		if info.IsDir() {
			yield(plugin.Artifact{}, fmt.Errorf("%s is a directory, not an SBOM file", s.opts.Target))
			return
		}
		dir := filepath.Dir(abs)
		yield(plugin.Artifact{
			Kind:    plugin.ArtifactSBOM,
			Root:    os.DirFS(dir),
			Path:    dir,
			Label:   s.opts.Target,
			Key:     abs,
			Include: []string{filepath.Base(abs)},
		}, nil)
	}
}
