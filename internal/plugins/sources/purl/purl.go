// Package purl is the source of one package URL, for example
// pkg:npm/lodash@4.17.21.
package purl

import (
	"context"
	"iter"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the registered name of the source.
const Name = "purl"

// Options configure the source.
type Options struct {
	Target string `json:"target"`
}

// Source yields one PURL artifact.
type Source struct {
	opts Options
}

// New returns the source.
func New(o Options) *Source { return &Source{opts: o} }

// Artifacts yields the PURL. The key is the PURL in its canonical form.
func (s *Source) Artifacts(context.Context) iter.Seq2[plugin.Artifact, error] {
	return func(yield func(plugin.Artifact, error) bool) {
		id, err := model.ParsePURL(s.opts.Target)
		if err != nil {
			yield(plugin.Artifact{}, err)
			return
		}
		yield(plugin.Artifact{
			Kind:  plugin.ArtifactPURL,
			Label: s.opts.Target,
			Key:   "purl:" + id.PURL(),
			PURL:  id.PURL(),
		}, nil)
	}
}
