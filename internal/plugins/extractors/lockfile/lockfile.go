// Package lockfile holds the graph-aware lockfile extractors. Each one is a
// copy of a Scalibr extractor with a patch that sets the parent ids of
// each package. Each copy keeps the Scalibr name, so it replaces the
// upstream extractor in the extractor set.
package lockfile

import (
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"

	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/bunlock"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/cargolock"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/packagelockjson"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/pnpmlock"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/uvlock"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile/yarnlock"
)

// Extractors returns the graph-aware lockfile extractors.
func Extractors() ([]filesystem.Extractor, error) {
	cfg := &cpb.PluginConfig{}
	var out []filesystem.Extractor
	for _, newFn := range []func(*cpb.PluginConfig) (filesystem.Extractor, error){
		packagelockjson.New,
		uvlock.New,
		cargolock.New,
		pnpmlock.New,
		yarnlock.New,
		bunlock.New,
	} {
		e, err := newFn(cfg)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
